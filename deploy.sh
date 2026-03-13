#!/bin/bash
# deploy.sh — THEAN SOC one-shot deployment script
# Usage: sudo bash deploy.sh
# Tested on: Ubuntu 22.04 / Debian 12
# -------------------------------------------------------

set -e  # Exit on any error
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC} $1"; }
ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()   { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# ── Must be root ──────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && err "Run as root: sudo bash deploy.sh"

APP_DIR="/opt/thean-soc"
APP_USER="thean"

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   THEAN SOC — Deployment Script              ║"
echo "║   Home Security Operations Center            ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# ── 1. System update ──────────────────────────────────────────────────────────
info "Updating system packages..."
apt-get update -qq && apt-get upgrade -y -qq
ok "System updated"

# ── 2. Install dependencies ───────────────────────────────────────────────────
info "Installing dependencies..."
apt-get install -y -qq \
    python3 python3-pip python3-venv \
    nginx certbot python3-certbot-nginx \
    ufw fail2ban git curl \
    libssl-dev libffi-dev
ok "Dependencies installed"

# ── 3. Create app user (no login shell) ──────────────────────────────────────
info "Creating app user..."
if ! id "$APP_USER" &>/dev/null; then
    useradd --system --shell /bin/false --home "$APP_DIR" --create-home "$APP_USER"
    ok "User '$APP_USER' created"
else
    warn "User '$APP_USER' already exists"
fi

# ── 4. Copy app files ─────────────────────────────────────────────────────────
info "Deploying application files..."
mkdir -p "$APP_DIR"/{data,logs,static,templates}
cp app.py security_core.py Homeme.html requirements.txt "$APP_DIR/"
chmod 750 "$APP_DIR"
chown -R "$APP_USER:$APP_USER" "$APP_DIR"
chmod 700 "$APP_DIR/data"    # data dir: owner only
chmod 750 "$APP_DIR/logs"
ok "Files deployed to $APP_DIR"

# ── 5. Python virtual environment ────────────────────────────────────────────
info "Creating Python virtual environment..."
sudo -u "$APP_USER" python3 -m venv "$APP_DIR/venv"
sudo -u "$APP_USER" "$APP_DIR/venv/bin/pip" install --quiet --upgrade pip
sudo -u "$APP_USER" "$APP_DIR/venv/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"
ok "Python venv ready"

# ── 6. Generate secrets ───────────────────────────────────────────────────────
info "Generating cryptographic secrets..."
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
ok "Secrets generated"

# ── 7. Install systemd service ────────────────────────────────────────────────
info "Installing systemd service..."
cp thean-soc.service /etc/systemd/system/thean-soc.service

# Inject real secrets into service file
sed -i "s/REPLACE_WITH_STRONG_SECRET_64CHARS/$SECRET_KEY/1" /etc/systemd/system/thean-soc.service
sed -i "s/REPLACE_WITH_STRONG_SECRET_64CHARS/$JWT_SECRET/1" /etc/systemd/system/thean-soc.service

systemctl daemon-reload
systemctl enable thean-soc
ok "Systemd service installed"

# ── 8. Initialize database ────────────────────────────────────────────────────
info "Initializing database..."
cd "$APP_DIR"
sudo -u "$APP_USER" SECRET_KEY="$SECRET_KEY" JWT_SECRET="$JWT_SECRET" \
    "$APP_DIR/venv/bin/python3" -c "
import sys; sys.path.insert(0, '.')
from app import init_db
init_db()
print('Database initialized')
"
chmod 600 "$APP_DIR/data/thean.db"
ok "Database ready"

# ── 9. Firewall (UFW) ─────────────────────────────────────────────────────────
info "Configuring firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh        # Keep SSH open!
ufw allow 80/tcp     # HTTP (redirect to HTTPS)
ufw allow 443/tcp    # HTTPS
# Block direct access to Flask port
ufw deny 5000/tcp
ufw --force enable
ok "UFW firewall configured"

# ── 10. Fail2Ban ──────────────────────────────────────────────────────────────
info "Configuring Fail2Ban..."
cat > /etc/fail2ban/jail.d/thean-soc.conf << 'EOF'
[thean-soc-login]
enabled   = true
port      = http,https
filter    = thean-soc-login
logpath   = /opt/thean-soc/logs/security.log
maxretry  = 5
findtime  = 300
bantime   = 3600
action    = iptables-multiport[name=thean, port="http,https"]

[nginx-http-auth]
enabled = true
maxretry = 5
bantime  = 3600

[nginx-botsearch]
enabled  = true
maxretry = 2
bantime  = 86400
EOF

# Custom filter for THEAN login failures
cat > /etc/fail2ban/filter.d/thean-soc-login.conf << 'EOF'
[Definition]
failregex = LOGIN_FAIL.* user=<HOST>
            RATE_LIMIT: <HOST>
            SCANNER: <HOST>
            AUTO-BLOCK: <HOST>
ignoreregex =
EOF

systemctl enable fail2ban
systemctl restart fail2ban
ok "Fail2Ban configured"

# ── 11. Nginx config ─────────────────────────────────────────────────────────
info "Configuring Nginx..."

# Add rate limiting zones to nginx.conf if not already there
if ! grep -q "limit_req_zone" /etc/nginx/nginx.conf; then
    sed -i '/http {/a\\n    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;\n    limit_req_zone $binary_remote_addr zone=login_limit:10m rate=1r/m;\n    limit_conn_zone $binary_remote_addr zone=conn_limit:10m;' /etc/nginx/nginx.conf
fi

cp nginx.conf /etc/nginx/sites-available/thean-soc
ln -sf /etc/nginx/sites-available/thean-soc /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

nginx -t && ok "Nginx config valid"

# ── 12. SSL Certificate ───────────────────────────────────────────────────────
echo ""
warn "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
warn "SSL SETUP — Enter your domain when prompted"
warn "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
read -p "Enter your domain (e.g. soc.yourdomain.com): " DOMAIN
if [ -n "$DOMAIN" ]; then
    sed -i "s/yourdomain.com/$DOMAIN/g" /etc/nginx/sites-available/thean-soc
    systemctl reload nginx
    certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --email "admin@$DOMAIN" || \
        warn "Certbot failed — configure SSL manually after DNS is set up"
    ok "SSL configured for $DOMAIN"
else
    warn "No domain entered — skipping SSL. Edit nginx.conf manually."
fi

# ── 13. Start everything ──────────────────────────────────────────────────────
info "Starting services..."
systemctl start thean-soc
systemctl reload nginx

sleep 2
if systemctl is-active --quiet thean-soc; then
    ok "THEAN SOC is running"
else
    err "Service failed to start. Check: sudo journalctl -u thean-soc -n 50"
fi

# ── 14. Kernel hardening (sysctl) ─────────────────────────────────────────────
info "Applying kernel security settings..."
cat > /etc/sysctl.d/99-thean-security.conf << 'EOF'
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
# Ignore source-routed packets
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
# Log martians (spoofed packets)
net.ipv4.conf.all.log_martians = 1
# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
# Time-wait assassination protection
net.ipv4.tcp_rfc1337 = 1
# Disable IPv6 if not needed
# net.ipv6.conf.all.disable_ipv6 = 1
EOF
sysctl --system -q
ok "Kernel hardened"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   ✅  THEAN SOC DEPLOYED SUCCESSFULLY                    ║"
echo "╠══════════════════════════════════════════════════════════╣"
if [ -n "$DOMAIN" ]; then
echo "║   URL:      https://$DOMAIN"
else
echo "║   URL:      http://YOUR_SERVER_IP  (add SSL first)"
fi
echo "║   Login:    admin / Admin@1234  (change immediately!)    ║"
echo "║   Viewer:   viewer / View@5678                           ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║   Useful commands:                                       ║"
echo "║   sudo systemctl status thean-soc                        ║"
echo "║   sudo journalctl -u thean-soc -f                        ║"
echo "║   sudo fail2ban-client status                            ║"
echo "║   sudo tail -f /opt/thean-soc/logs/security.log          ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
warn "⚠ CHANGE THE DEFAULT PASSWORDS IMMEDIATELY after first login!"
echo ""
