<a href="Homeme.html">To live this web</a>
# THEAN SOC — Home Security Operations Center
### Full-Stack Deployment Guide

---

## What's Included

| File | Purpose |
|------|---------|
| `app.py` | Flask backend — all API routes, database, JWT auth |
| `security_core.py` | Anti-hacker defense layer |
| `Homeme.html` | Frontend — serves from Flask |
| `requirements.txt` | Python dependencies |
| `nginx.conf` | Production reverse proxy config |
| `thean-soc.service` | Systemd service (auto-start on boot) |
| `deploy.sh` | One-command deployment script |

---

## Quick Start (Local Testing)

```bash
# 1. Install Python deps
pip install -r requirements.txt

# 2. Run the server
python app.py

# 3. Open browser
open http://localhost:5000

# Login: admin / Admin@1234
```

---

## Production Deployment (Ubuntu/Debian VPS)

### Requirements
- Ubuntu 22.04 or Debian 12 VPS
- A domain name pointed at your server's IP
- Root or sudo access

### One-Command Deploy

```bash
# Upload files to your server
scp -r thean_soc/ user@yourserver.com:/tmp/

# SSH in and run
ssh user@yourserver.com
cd /tmp/thean_soc
sudo bash deploy.sh
```

The script handles everything:
- System hardening
- Python virtual environment
- Database initialization
- SSL certificate (Let's Encrypt)
- Nginx reverse proxy
- Firewall (UFW)
- Fail2Ban intrusion prevention
- Systemd service (auto-restart on crash/reboot)
- Kernel network hardening

---

## Security Architecture

```
INTERNET
    │
    ▼
[Cloudflare / DNS]     ← Optional: Add Cloudflare for extra DDoS protection
    │
    ▼
[UFW Firewall]         ← Only ports 80, 443, 22 open
    │
    ▼
[Fail2Ban]             ← Auto-bans IPs with repeated failures
    │
    ▼
[Nginx]                ← SSL termination, rate limiting, scanner blocking
    │
    ▼
[security_core.py]     ← Request inspection, bot detection, input sanitization
    │
    ▼
[Flask app.py]         ← JWT auth, bcrypt passwords, encrypted vault
    │
    ▼
[SQLite + Fernet]      ← Encrypted secrets, hash-chained audit log
```

---

## What It Defends Against

### Network Layer (Nginx + UFW)
| Attack | Defense |
|--------|---------|
| DDoS | Rate limiting (10 req/s global, 1/min login) |
| Port scanning | UFW blocks all non-HTTP/HTTPS ports |
| Scanner tools | User-agent blocking (sqlmap, nikto, nmap, etc.) |
| Directory traversal | Bad path blocking in Nginx |

### Application Layer (security_core.py)
| Attack | Defense |
|--------|---------|
| SQL Injection | Regex pattern detection + parameterized queries |
| XSS | Input sanitization + CSP headers |
| CSRF | Double-submit cookie pattern |
| Brute Force | Token bucket rate limiter per IP |
| Credential Stuffing | Account lockout after 5 fails (15 min) |
| Session Hijacking | JWT with jti (replay prevention) + revokable sessions |
| Clickjacking | `X-Frame-Options: DENY` |
| MIME Sniffing | `X-Content-Type-Options: nosniff` |
| Information Leakage | No stack traces to client, generic error messages |
| Path Traversal | Pattern detection + nginx blocking |
| Bot/Scanner | User-agent + path pattern detection + 24h auto-ban |
| Honeypot bypass | Hidden form field catches bots |

### Data Layer
| Feature | Implementation |
|---------|---------------|
| Passwords | bcrypt (rounds=12) — industry standard |
| Secrets | AES-256 via Fernet (symmetric encryption) |
| Sessions | SQLite with revocation support |
| Audit Log | SHA-256 hash chain — tamper-detectable |
| 2FA | TOTP (Google Authenticator compatible) |

---

## Changing Default Passwords

After first login, go to **Users** page → click your username → change password.

Or via the API:
```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin@1234"}'
# Copy the token from response, then:
curl -X POST http://localhost:5000/api/security/users \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"newadmin","password":"YourStr0ng!Pass","role":"admin"}'
```

---

## Optional: Cloudflare (Recommended)

For maximum protection:
1. Sign up at cloudflare.com (free)
2. Add your domain and update nameservers
3. Enable "Under Attack Mode" if being targeted
4. Enable "Bot Fight Mode"
5. Set SSL/TLS to "Full (Strict)"

---

## Monitoring

```bash
# Watch the app logs live
sudo journalctl -u thean-soc -f

# Watch security events
sudo tail -f /opt/thean-soc/logs/security.log

# See who's been banned by Fail2Ban
sudo fail2ban-client status thean-soc-login

# Check Nginx for suspicious traffic
sudo tail -f /var/log/nginx/thean_access.log | grep -v "200\|304"

# App health check
curl http://localhost:5000/api/security/dashboard -H "Authorization: Bearer TOKEN"
```

---

## Service Management

```bash
sudo systemctl start thean-soc      # start
sudo systemctl stop thean-soc       # stop
sudo systemctl restart thean-soc    # restart
sudo systemctl status thean-soc     # check status
sudo systemctl enable thean-soc     # auto-start on boot
```

---

## Default Credentials

| User | Password | Role |
|------|----------|------|
| admin | Admin@1234 | Admin (full access) |
| viewer | View@5678 | Read-only |

**Change these immediately in production!**

---

## Environment Variables (Production)

Set in `/etc/systemd/system/thean-soc.service`:

```
SECRET_KEY=<64 hex chars>    # Flask session secret
JWT_SECRET=<64 hex chars>    # JWT signing secret
ALLOWED_ORIGINS=https://yourdomain.com   # CORS whitelist
```

Generate new secrets:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

---

## File Permissions (Production)

```
/opt/thean-soc/
├── app.py              640  thean:thean
├── security_core.py    640  thean:thean
├── Homeme.html         644  thean:thean
├── data/               700  thean:thean   ← restricted
│   ├── thean.db        600  thean:thean   ← DB owner only
│   └── .fernet_key     600  thean:thean   ← key owner only
└── logs/               750  thean:thean
```
