"""
app.py — THEAN SOC Full-Stack Backend
======================================
Run:  python app.py
Deps: pip install flask flask-cors cryptography pyotp pyjwt bcrypt
"""

import os
import re
import time
import json
import hmac
import pyotp
import bcrypt
import sqlite3
import hashlib
import secrets
import logging
import jwt as pyjwt

from datetime import datetime, timedelta
from pathlib import Path
from functools import wraps
from cryptography.fernet import Fernet

from flask import (Flask, request, jsonify, send_from_directory,
                   g, abort, make_response)
from flask_cors import CORS

from security_core import (
    rate_limiter, sanitizer, csrf, inspector,
    apply_security_headers, require_rate_limit,
    require_no_scanner, require_auth, require_admin,
    get_real_ip, check_honeypot, security_logger,
    setup_security_logging, detect_scanner, BOT_UA_PATTERNS
)

# ── App init ──────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder='static', template_folder='templates')

# Disable debug mode in production!
app.config['DEBUG']   = False
app.config['TESTING'] = False

# Secret key — CHANGE THIS in production! Use: python -c "import secrets; print(secrets.token_hex(32))"
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# JWT settings
JWT_SECRET    = os.environ.get('JWT_SECRET', secrets.token_hex(32))
JWT_ALGORITHM = 'HS256'
JWT_TTL       = 6 * 3600  # 6 hours

# CORS — restrict to your domain in production
CORS(app, resources={r'/api/*': {
    'origins': os.environ.get('ALLOWED_ORIGINS', 'http://localhost:5000').split(','),
    'methods': ['GET', 'POST', 'DELETE'],
    'allow_headers': ['Content-Type', 'Authorization', 'X-CSRF-Token'],
    'supports_credentials': True
}})

# Logging
logging.basicConfig(level=logging.INFO)
setup_security_logging()
logger = logging.getLogger('thean.app')

# ── Directory setup ───────────────────────────────────────────────────────────
DATA_DIR = Path('data')
LOG_DIR  = Path('logs')
DATA_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)

DB_PATH    = DATA_DIR / 'thean.db'
FERNET_KEY = DATA_DIR / '.fernet_key'

# ── Encryption Key ────────────────────────────────────────────────────────────
def load_or_create_fernet() -> Fernet:
    if FERNET_KEY.exists():
        key = FERNET_KEY.read_bytes()
    else:
        key = Fernet.generate_key()
        FERNET_KEY.write_bytes(key)
        os.chmod(FERNET_KEY, 0o600)  # owner read-only
    return Fernet(key)

fernet = load_or_create_fernet()

# ── Database ──────────────────────────────────────────────────────────────────
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(str(DB_PATH))
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA journal_mode=WAL')
        g.db.execute('PRAGMA foreign_keys=ON')
        # Prevent SQL injection at DB level too
        g.db.execute('PRAGMA secure_delete=ON')
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db: db.close()

def init_db():
    db = sqlite3.connect(str(DB_PATH))
    db.executescript("""
    PRAGMA journal_mode=WAL;
    PRAGMA foreign_keys=ON;
    PRAGMA secure_delete=ON;

    CREATE TABLE IF NOT EXISTS users (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        username     TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role         TEXT DEFAULT 'viewer' CHECK(role IN ('admin','viewer')),
        totp_secret  TEXT,
        totp_enabled INTEGER DEFAULT 0,
        fail_count   INTEGER DEFAULT 0,
        locked_until TEXT,
        last_login   TEXT,
        created_at   TEXT DEFAULT (datetime('now')),
        last_ip      TEXT
    );

    CREATE TABLE IF NOT EXISTS sessions (
        id          TEXT PRIMARY KEY,
        user_id     INTEGER REFERENCES users(id) ON DELETE CASCADE,
        ip_address  TEXT,
        user_agent  TEXT,
        created_at  TEXT DEFAULT (datetime('now')),
        expires_at  TEXT NOT NULL,
        revoked     INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS threats (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp    TEXT DEFAULT (datetime('now')),
        ip_address   TEXT,
        event_type   TEXT,
        severity     TEXT,
        threat_score INTEGER DEFAULT 0,
        details      TEXT,
        resolved     INTEGER DEFAULT 0,
        resolved_by  TEXT,
        resolved_at  TEXT
    );

    CREATE TABLE IF NOT EXISTS firewall_rules (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_type   TEXT NOT NULL,
        value       TEXT NOT NULL,
        action      TEXT NOT NULL CHECK(action IN ('block','allow')),
        hits        INTEGER DEFAULT 0,
        description TEXT,
        created_by  TEXT,
        created_at  TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS audit_log (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp  TEXT DEFAULT (datetime('now')),
        action     TEXT NOT NULL,
        username   TEXT,
        ip_address TEXT,
        user_agent TEXT,
        result     TEXT,
        resource   TEXT,
        details    TEXT,
        prev_hash  TEXT,
        entry_hash TEXT
    );

    CREATE TABLE IF NOT EXISTS vault (
        key_name    TEXT PRIMARY KEY,
        ciphertext  TEXT NOT NULL,
        created_at  TEXT DEFAULT (datetime('now')),
        updated_at  TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS room_states (
        room_id    TEXT NOT NULL,
        device     TEXT NOT NULL,
        state      INTEGER DEFAULT 1,
        updated_at TEXT DEFAULT (datetime('now')),
        updated_by TEXT,
        PRIMARY KEY (room_id, device)
    );

    CREATE INDEX IF NOT EXISTS idx_threats_ip ON threats(ip_address);
    CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(username);
    CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
    """)

    # Seed default admin user (password: Admin@1234)
    pw = bcrypt.hashpw(b'Admin@1234', bcrypt.gensalt(rounds=12)).decode()
    db.execute("""
        INSERT OR IGNORE INTO users (username, password_hash, role, totp_enabled)
        VALUES (?, ?, 'admin', 0)
    """, ('admin', pw))

    # Seed viewer user (password: View@5678)
    pw2 = bcrypt.hashpw(b'View@5678', bcrypt.gensalt(rounds=12)).decode()
    db.execute("""
        INSERT OR IGNORE INTO users (username, password_hash, role, totp_enabled)
        VALUES (?, ?, 'viewer', 0)
    """, ('viewer', pw2))

    # Seed default firewall rules
    db.execute("""INSERT OR IGNORE INTO firewall_rules (id,rule_type,value,action,description)
                  VALUES (1,'ip_block','0.0.0.0','block','Block null IP')""")

    # Seed default room states
    rooms_devices = {
        'living_room':    ['lights','camera','motion','lock'],
        'kitchen':        ['lights','smoke','gas','appliances'],
        'bedroom_master': ['lights','camera','windows','climate'],
        'garage':         ['lights','door','motion','vehicle'],
        'office':         ['lights','network','webcam','lock'],
        'bathroom':       ['lights','leak','fan','temp'],
    }
    for room, devices in rooms_devices.items():
        for device in devices:
            db.execute("""INSERT OR IGNORE INTO room_states (room_id, device, state)
                          VALUES (?,?,1)""", (room, device))

    db.commit()
    db.close()
    logger.info('Database initialized')


# ── JWT helpers ───────────────────────────────────────────────────────────────
def create_token(user_id: int, username: str, role: str, session_id: str) -> str:
    payload = {
        'sub': user_id,
        'username': username,
        'role': role,
        'sid': session_id,
        'iat': int(time.time()),
        'exp': int(time.time()) + JWT_TTL,
        'jti': secrets.token_hex(16)  # JWT ID — prevents replay
    }
    return pyjwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_token(token: str) -> dict | None:
    try:
        payload = pyjwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        # Check session not revoked in DB
        db = get_db()
        row = db.execute(
            'SELECT revoked FROM sessions WHERE id=?', (payload.get('sid'),)
        ).fetchone()
        if not row or row['revoked']:
            return None
        return payload
    except pyjwt.ExpiredSignatureError:
        return None
    except pyjwt.InvalidTokenError:
        return None


# ── Audit log (hash-chained) ──────────────────────────────────────────────────
def audit(action: str, result: str, resource: str = '', details: str = ''):
    """Write a tamper-evident audit entry with hash chain."""
    try:
        db   = get_db()
        user = getattr(g, 'user', None)
        ip   = get_real_ip()
        ua   = request.headers.get('User-Agent', '')[:200]

        # Get last hash
        last = db.execute('SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1').fetchone()
        prev_hash = last['entry_hash'] if last else '0' * 64

        # Build entry string and hash it (chain)
        entry_str = f"{datetime.utcnow().isoformat()}|{action}|{user['username'] if user else ''}|{ip}|{result}|{resource}|{prev_hash}"
        entry_hash = hashlib.sha256(entry_str.encode()).hexdigest()

        db.execute("""
            INSERT INTO audit_log (action, username, ip_address, user_agent, result, resource, details, prev_hash, entry_hash)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (
            action,
            user['username'] if user else None,
            ip, ua, result, resource, details, prev_hash, entry_hash
        ))
        db.commit()
    except Exception as e:
        logger.error(f'Audit write failed: {e}')


# ── Global request hooks ──────────────────────────────────────────────────────
@app.before_request
def global_security_checks():
    ip = get_real_ip()

    # Block known scanners on ALL routes
    ua   = request.headers.get('User-Agent', '')
    path = request.path
    is_scanner, reason = detect_scanner(ua, path)
    if is_scanner:
        security_logger.warning(f'SCANNER: {ip} — {reason}')
        rate_limiter._blocked[ip] = time.time() + 86400
        abort(403)

    # Rate limit everything at 20 req/s
    allowed, msg = rate_limiter.check(ip, cost=1.0, rate=20.0, capacity=60.0)
    if not allowed:
        security_logger.warning(f'GLOBAL_RATE_LIMIT: {ip}')
        abort(429)

    # Inspect request for threats
    score, reasons = inspector.score(request)
    if score >= 80:
        security_logger.warning(f'HIGH_THREAT: {ip} score={score} — {reasons}')
        rate_limiter.record_fail(ip, threshold=3, window=60)
        abort(403)
    elif score >= 50:
        security_logger.warning(f'MED_THREAT: {ip} score={score} — {reasons}')

    # Content-Type check on POST
    if request.method == 'POST' and request.content_length:
        ct = request.content_type or ''
        if 'application/json' not in ct and request.path.startswith('/api/'):
            abort(415)

    # Max body size: 64KB
    if request.content_length and request.content_length > 65536:
        abort(413)


@app.after_request
def after_request(response):
    return apply_security_headers(response)


# ── Error handlers ────────────────────────────────────────────────────────────
@app.errorhandler(400)
def bad_request(e):     return jsonify(error='Bad request'), 400

@app.errorhandler(401)
def unauthorized(e):    return jsonify(error='Authentication required'), 401

@app.errorhandler(403)
def forbidden(e):       return jsonify(error='Forbidden'), 403

@app.errorhandler(404)
def not_found(e):
    # Don't reveal path info
    return jsonify(error='Not found'), 404

@app.errorhandler(405)
def method_not_allowed(e): return jsonify(error='Method not allowed'), 405

@app.errorhandler(413)
def too_large(e):       return jsonify(error='Request too large'), 413

@app.errorhandler(415)
def unsupported_media(e): return jsonify(error='Content-Type must be application/json'), 415

@app.errorhandler(429)
def rate_limited(e):    return jsonify(error='Too many requests. Please slow down.'), 429

@app.errorhandler(500)
def server_error(e):
    # Never expose stack traces to client
    logger.error(f'500 error: {e}')
    return jsonify(error='Internal server error'), 500


# ── Static files ──────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return send_from_directory('.', 'Homeme.html')

@app.route('/favicon.ico')
def favicon():
    return '', 204


# ══════════════════════════════════════════════════════════════════════════════
#   AUTH ROUTES
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/api/auth/login', methods=['POST'])
@require_no_scanner
@require_rate_limit(cost=3.0, rate=0.5, capacity=5.0)  # Strict: 1 login per 2 sec
def login():
    ip   = get_real_ip()
    data = request.get_json(silent=True) or {}

    # Honeypot check
    if check_honeypot(data):
        security_logger.warning(f'HONEYPOT: {ip}')
        rate_limiter._blocked[ip] = time.time() + 3600
        return jsonify(error='Forbidden'), 403

    username = data.get('username', '')
    password = data.get('password', '')
    totp_code = data.get('totp', '')

    # Sanitize inputs
    username, err = sanitizer.sanitize_input(username, max_len=32)
    if err: return jsonify(error=err), 400

    # Validate username format
    valid, msg = sanitizer.validate_username(username)
    if not valid: return jsonify(error=msg), 400

    db = get_db()

    # Timing-safe user lookup
    user = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()

    # Timing-safe: always run bcrypt even if user not found (prevent timing oracle)
    dummy_hash = b'$2b$12$' + b'x' * 53
    pw_hash = user['password_hash'].encode() if user else dummy_hash

    # Check if locked
    if user and user['locked_until']:
        locked_dt = datetime.fromisoformat(user['locked_until'])
        if datetime.utcnow() < locked_dt:
            wait = int((locked_dt - datetime.utcnow()).total_seconds())
            audit('login', 'fail_locked', 'auth', f'Locked user attempt: {username}')
            return jsonify(error=f'Account locked. Try again in {wait}s.'), 403

    # Verify password
    try:
        pw_match = bcrypt.checkpw(password.encode()[:72], pw_hash)
    except Exception:
        pw_match = False

    if not user or not pw_match:
        blocked, count = rate_limiter.record_fail(ip, threshold=10, window=300)
        if user:
            fail_count = user['fail_count'] + 1
            lock_until = None
            if fail_count >= 5:
                lock_until = (datetime.utcnow() + timedelta(minutes=15)).isoformat()
                security_logger.warning(f'ACCOUNT_LOCK: {username} after {fail_count} fails')
            db.execute('UPDATE users SET fail_count=?, locked_until=? WHERE id=?',
                       (fail_count, lock_until, user['id']))
            db.commit()
        audit('login', 'fail', 'auth', f'Bad credentials for {username}')
        security_logger.warning(f'LOGIN_FAIL: {ip} user={username}')
        # Generic error — don't reveal whether user exists
        return jsonify(error='Invalid credentials'), 401

    # TOTP check
    if user['totp_enabled'] and user['totp_secret']:
        if not totp_code:
            return jsonify(error='TOTP code required', totp_required=True), 401
        totp = pyotp.TOTP(user['totp_secret'])
        if not totp.verify(totp_code, valid_window=1):
            audit('login', 'fail_totp', 'auth', username)
            rate_limiter.record_fail(ip, threshold=10, window=300)
            return jsonify(error='Invalid TOTP code'), 401

    # Success — create session
    session_id = secrets.token_urlsafe(32)
    expires_at = (datetime.utcnow() + timedelta(seconds=JWT_TTL)).isoformat()
    ua = request.headers.get('User-Agent', '')[:200]

    db.execute("""
        INSERT INTO sessions (id, user_id, ip_address, user_agent, expires_at)
        VALUES (?,?,?,?,?)
    """, (session_id, user['id'], ip, ua, expires_at))
    db.execute("UPDATE users SET fail_count=0, locked_until=NULL, last_login=datetime('now'), last_ip=? WHERE id=?",
               (ip, user['id']))
    db.commit()

    token = create_token(user['id'], user['username'], user['role'], session_id)

    audit('login', 'success', 'auth', username)
    security_logger.info(f'LOGIN_OK: {ip} user={username}')

    return jsonify(
        token=token,
        user={'id': user['id'], 'username': user['username'], 'role': user['role']}
    )


@app.route('/api/auth/logout', methods=['POST'])
@require_auth
def logout():
    sid = g.user.get('sid')
    if sid:
        db = get_db()
        db.execute('UPDATE sessions SET revoked=1 WHERE id=?', (sid,))
        db.commit()
    audit('logout', 'success', 'auth')
    return jsonify(success=True)


@app.route('/api/auth/totp/setup', methods=['POST'])
@require_auth
def setup_totp():
    if g.user['role'] != 'admin':
        return jsonify(error='Admin only'), 403
    db = get_db()
    secret = pyotp.random_base32()
    db.execute('UPDATE users SET totp_secret=? WHERE id=?', (secret, g.user['sub']))
    db.commit()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=g.user['username'], issuer_name='THEAN SOC'
    )
    audit('totp_setup', 'success', f'user/{g.user["sub"]}')
    return jsonify(secret=secret, uri=uri)


@app.route('/api/auth/totp/enable', methods=['POST'])
@require_auth
def enable_totp():
    data = request.get_json(silent=True) or {}
    code = data.get('code', '')
    db   = get_db()
    user = db.execute('SELECT * FROM users WHERE id=?', (g.user['sub'],)).fetchone()
    if not user or not user['totp_secret']:
        return jsonify(error='TOTP not set up'), 400
    totp = pyotp.TOTP(user['totp_secret'])
    if not totp.verify(code, valid_window=1):
        return jsonify(error='Invalid TOTP code'), 400
    db.execute('UPDATE users SET totp_enabled=1 WHERE id=?', (g.user['sub'],))
    db.commit()
    audit('totp_enable', 'success', f'user/{g.user["sub"]}')
    return jsonify(success=True)


# ── Password strength (no auth needed) ───────────────────────────────────────
@app.route('/api/security/password-strength', methods=['POST'])
@require_rate_limit(cost=1.0, rate=5.0, capacity=20.0)
def password_strength():
    data = request.get_json(silent=True) or {}
    pw   = data.get('password', '')
    valid, msg = sanitizer.validate_password(pw)
    score  = 0
    issues = []
    if len(pw) >= 8:  score += 25
    else: issues.append('Min 8 characters')
    if re.search(r'[A-Z]', pw): score += 25
    else: issues.append('Add uppercase letter')
    if re.search(r'[0-9]', pw): score += 25
    else: issues.append('Add a number')
    if re.search(r'[^A-Za-z0-9]', pw): score += 25
    else: issues.append('Add a special character')
    labels = {25:'Weak', 50:'Fair', 75:'Strong', 100:'Excellent'}
    return jsonify(score=score, label=labels.get(score,'Weak'), issues=issues, valid=valid)


# ══════════════════════════════════════════════════════════════════════════════
#   DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/api/security/dashboard')
@require_auth
def dashboard():
    db = get_db()
    threats_unresolved = db.execute('SELECT COUNT(*) FROM threats WHERE resolved=0').fetchone()[0]
    threats_total      = db.execute('SELECT COUNT(*) FROM threats').fetchone()[0]
    threats_critical   = db.execute("SELECT COUNT(*) FROM threats WHERE resolved=0 AND severity='HIGH'").fetchone()[0]
    recent_threats     = db.execute('SELECT * FROM threats ORDER BY id DESC LIMIT 5').fetchall()
    firewall_blocks    = db.execute('SELECT COALESCE(SUM(hits),0) FROM firewall_rules').fetchone()[0]
    active_sessions    = db.execute("SELECT COUNT(*) FROM sessions WHERE revoked=0 AND expires_at > datetime('now')").fetchone()[0]
    user_count         = db.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    audit_count        = db.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0]
    recent_audit       = db.execute('SELECT * FROM audit_log ORDER BY id DESC LIMIT 10').fetchall()
    threat_by_type     = db.execute('SELECT event_type, COUNT(*) as count FROM threats GROUP BY event_type').fetchall()

    return jsonify(
        threats={
            'unresolved': threats_unresolved, 'total': threats_total,
            'critical': threats_critical,
            'recent': [dict(t) for t in recent_threats]
        },
        firewall_blocks=firewall_blocks,
        active_sessions=active_sessions,
        user_count=user_count,
        audit_count=audit_count,
        recent_audit=[dict(a) for a in recent_audit],
        threat_by_type=[dict(t) for t in threat_by_type]
    )


# ══════════════════════════════════════════════════════════════════════════════
#   THREATS
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/api/security/threats')
@require_auth
def get_threats():
    db = get_db()
    rows = db.execute('SELECT * FROM threats ORDER BY id DESC LIMIT 100').fetchall()
    return jsonify(recent=[dict(r) for r in rows])


@app.route('/api/security/threats/<int:threat_id>/resolve', methods=['POST'])
@require_auth
def resolve_threat(threat_id):
    db = get_db()
    db.execute("UPDATE threats SET resolved=1, resolved_by=?, resolved_at=datetime('now') WHERE id=?",
               (g.user['username'], threat_id))
    db.commit()
    audit('threat_resolve', 'success', f'threat/{threat_id}')
    return jsonify(success=True)


# ══════════════════════════════════════════════════════════════════════════════
#   FIREWALL
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/api/security/firewall')
@require_auth
def get_firewall():
    db = get_db()
    rules = db.execute('SELECT * FROM firewall_rules ORDER BY id DESC').fetchall()
    return jsonify([dict(r) for r in rules])


@app.route('/api/security/firewall', methods=['POST'])
@require_admin
def add_firewall_rule():
    data = request.get_json(silent=True) or {}
    rule_type   = data.get('rule_type', '')
    value       = data.get('value', '')
    action      = data.get('action', 'block')
    description = data.get('description', '')

    # Validate
    if rule_type not in ('ip_block', 'user_agent', 'path_pattern'):
        return jsonify(error='Invalid rule type'), 400
    value, err = sanitizer.sanitize_input(value, max_len=256)
    if err: return jsonify(error=err), 400
    if not value: return jsonify(error='Value required'), 400
    if action not in ('block', 'allow'):
        return jsonify(error='Invalid action'), 400

    description, _ = sanitizer.sanitize_input(description, max_len=256)

    db = get_db()
    cur = db.execute("""
        INSERT INTO firewall_rules (rule_type, value, action, description, created_by)
        VALUES (?,?,?,?,?)
    """, (rule_type, value, action, description, g.user['username']))
    db.commit()
    audit('fw_rule_add', 'success', f'firewall/{cur.lastrowid}', f'{action} {value}')
    return jsonify(id=cur.lastrowid, success=True)


@app.route('/api/security/firewall/<int:rule_id>', methods=['DELETE'])
@require_admin
def delete_firewall_rule(rule_id):
    db = get_db()
    db.execute('DELETE FROM firewall_rules WHERE id=?', (rule_id,))
    db.commit()
    audit('fw_rule_delete', 'success', f'firewall/{rule_id}')
    return jsonify(success=True)


# ══════════════════════════════════════════════════════════════════════════════
#   USERS
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/api/security/users')
@require_admin
def get_users():
    db = get_db()
    users = db.execute(
        'SELECT id, username, role, totp_enabled, fail_count, locked_until, last_login, created_at FROM users'
    ).fetchall()
    return jsonify([dict(u) for u in users])


@app.route('/api/security/users', methods=['POST'])
@require_admin
def create_user():
    data = request.get_json(silent=True) or {}
    username = data.get('username', '')
    password = data.get('password', '')
    role     = data.get('role', 'viewer')

    # Validate
    username, err = sanitizer.sanitize_input(username, max_len=32)
    if err: return jsonify(error=err), 400
    valid, msg = sanitizer.validate_username(username)
    if not valid: return jsonify(error=msg), 400
    valid, msg = sanitizer.validate_password(password)
    if not valid: return jsonify(error=msg), 400
    if role not in ('admin', 'viewer'):
        return jsonify(error='Invalid role'), 400

    pw_hash = bcrypt.hashpw(password.encode()[:72], bcrypt.gensalt(rounds=12)).decode()
    db = get_db()
    try:
        cur = db.execute(
            'INSERT INTO users (username, password_hash, role) VALUES (?,?,?)',
            (username, pw_hash, role)
        )
        db.commit()
        audit('user_create', 'success', f'user/{cur.lastrowid}', username)
        return jsonify(id=cur.lastrowid, username=username, role=role)
    except sqlite3.IntegrityError:
        return jsonify(error='Username already exists'), 409


@app.route('/api/security/users/<int:user_id>/unlock', methods=['POST'])
@require_admin
def unlock_user(user_id):
    db = get_db()
    db.execute('UPDATE users SET locked_until=NULL, fail_count=0 WHERE id=?', (user_id,))
    db.commit()
    audit('user_unlock', 'success', f'user/{user_id}')
    return jsonify(success=True)


# ══════════════════════════════════════════════════════════════════════════════
#   SESSIONS
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/api/security/sessions')
@require_admin
def get_sessions():
    db = get_db()
    rows = db.execute("""
        SELECT s.*, u.username FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.revoked=0 AND s.expires_at > datetime('now')
        ORDER BY s.created_at DESC
    """).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route('/api/security/sessions/<session_id>/revoke', methods=['POST'])
@require_admin
def revoke_session(session_id):
    session_id, err = sanitizer.sanitize_input(session_id, max_len=64)
    if err: return jsonify(error=err), 400
    db = get_db()
    db.execute('UPDATE sessions SET revoked=1 WHERE id=?', (session_id,))
    db.commit()
    audit('session_revoke', 'success', f'session/{session_id[:12]}')
    return jsonify(success=True)


# ══════════════════════════════════════════════════════════════════════════════
#   AUDIT LOG
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/api/security/audit')
@require_admin
def get_audit():
    limit  = min(int(request.args.get('limit', 50)), 500)
    offset = int(request.args.get('offset', 0))
    db = get_db()
    entries = db.execute(
        'SELECT * FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?', (limit, offset)
    ).fetchall()
    total = db.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0]
    return jsonify(entries=[dict(e) for e in entries], total=total)


@app.route('/api/security/audit/verify')
@require_admin
def verify_audit():
    """Verify hash chain integrity."""
    db = get_db()
    entries = db.execute('SELECT * FROM audit_log ORDER BY id ASC').fetchall()
    issues  = []
    prev    = '0' * 64

    for e in entries:
        entry_str = f"{e['timestamp']}|{e['action']}|{e['username'] or ''}|{e['ip_address'] or ''}|{e['result'] or ''}|{e['resource'] or ''}|{prev}"
        expected  = hashlib.sha256(entry_str.encode()).hexdigest()
        if e['entry_hash'] != expected:
            issues.append(f'Entry #{e["id"]} hash mismatch')
        prev = e['entry_hash']

    return jsonify(valid=len(issues) == 0, entries=len(entries), issues=issues)


# ══════════════════════════════════════════════════════════════════════════════
#   ENCRYPTED VAULT
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/api/security/vault', methods=['POST'])
@require_admin
def save_secret():
    data  = request.get_json(silent=True) or {}
    key   = data.get('key', '')
    value = data.get('value', '')

    key, err = sanitizer.sanitize_input(key, max_len=64)
    if err: return jsonify(error=err), 400
    if not re.match(r'^[a-zA-Z0-9_\-\.]+$', key):
        return jsonify(error='Key name: alphanumeric, _, -, . only'), 400
    if not value:
        return jsonify(error='Value required'), 400

    ciphertext = fernet.encrypt(value.encode()).decode()
    db = get_db()
    db.execute("""
        INSERT INTO vault (key_name, ciphertext) VALUES (?,?)
        ON CONFLICT(key_name) DO UPDATE SET ciphertext=excluded.ciphertext, updated_at=datetime('now')
    """, (key, ciphertext))
    db.commit()
    audit('vault_write', 'success', f'vault/{key}')
    return jsonify(success=True)


@app.route('/api/security/vault/<key_name>')
@require_admin
def read_secret(key_name):
    key_name, err = sanitizer.sanitize_input(key_name, max_len=64)
    if err: return jsonify(error=err), 400
    db  = get_db()
    row = db.execute('SELECT * FROM vault WHERE key_name=?', (key_name,)).fetchone()
    if not row:
        return jsonify(error=f'Key not found: {key_name}'), 404
    try:
        plaintext = fernet.decrypt(row['ciphertext'].encode()).decode()
    except Exception:
        return jsonify(error='Decryption failed'), 500
    audit('vault_read', 'success', f'vault/{key_name}')
    return jsonify(key=key_name, value=plaintext)


# ══════════════════════════════════════════════════════════════════════════════
#   ROOM CONTROL
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/api/rooms')
@require_auth
def get_rooms():
    db   = get_db()
    rows = db.execute('SELECT room_id, device, state FROM room_states').fetchall()
    result = {}
    for r in rows:
        result.setdefault(r['room_id'], {})[r['device']] = bool(r['state'])
    return jsonify(result)


@app.route('/api/rooms/<room_id>/<device>', methods=['POST'])
@require_auth
def set_device(room_id, device):
    room_id, err = sanitizer.sanitize_input(room_id, max_len=32)
    if err: return jsonify(error=err), 400
    device,  err = sanitizer.sanitize_input(device, max_len=32)
    if err: return jsonify(error=err), 400

    if not re.match(r'^[a-z_]+$', room_id) or not re.match(r'^[a-z_]+$', device):
        return jsonify(error='Invalid room or device name'), 400

    data  = request.get_json(silent=True) or {}
    state = 1 if data.get('state', True) else 0

    db = get_db()
    db.execute("""
        INSERT INTO room_states (room_id, device, state, updated_at, updated_by)
        VALUES (?,?,?,datetime('now'),?)
        ON CONFLICT(room_id, device) DO UPDATE SET state=excluded.state, updated_at=excluded.updated_at, updated_by=excluded.updated_by
    """, (room_id, device, state, g.user['username']))
    db.commit()
    audit('device_toggle', 'success', f'{room_id}/{device}', f'state={state}')

    # Auto-log threats for critical safety device disable
    critical = {'smoke', 'gas', 'leak'}
    if device in critical and state == 0:
        db.execute("""
            INSERT INTO threats (ip_address, event_type, severity, threat_score, details)
            VALUES (?,?,?,?,?)
        """, (get_real_ip(), 'safety_device_disabled', 'HIGH', 70,
              f'{device} disabled in {room_id} by {g.user["username"]}'))
        db.commit()

    return jsonify(success=True, room_id=room_id, device=device, state=bool(state))


@app.route('/api/rooms/global', methods=['POST'])
@require_auth
def set_global_room_mode():
    data = request.get_json(silent=True) or {}
    mode = data.get('mode', '')
    if mode not in ('secure', 'standby', 'alert'):
        return jsonify(error='Invalid mode'), 400

    db = get_db()
    if mode == 'secure':
        devices_on = ['lock','camera','motion','smoke','gas','windows','vehicle','network','webcam','leak']
        db.execute(f"UPDATE room_states SET state=1 WHERE device IN ({','.join('?'*len(devices_on))})", devices_on)
    elif mode == 'standby':
        db.execute("UPDATE room_states SET state=0")
        for d in ['lock','smoke','gas','leak']:
            db.execute("UPDATE room_states SET state=1 WHERE device=?", (d,))
    elif mode == 'alert':
        db.execute("UPDATE room_states SET state=0")
        for d in ['smoke','gas','leak','motion','camera']:
            db.execute("UPDATE room_states SET state=1 WHERE device=?", (d,))

    db.execute("UPDATE room_states SET updated_at=datetime('now'), updated_by=?", (g.user['username'],))
    db.commit()
    audit('global_room_mode', 'success', 'rooms', mode)
    return jsonify(success=True, mode=mode)


# ══════════════════════════════════════════════════════════════════════════════
#   INTERNAL: Record incoming threats from firewall checks
# ══════════════════════════════════════════════════════════════════════════════
def record_threat(ip: str, event_type: str, severity: str, score: int, details: str = ''):
    """Called internally to log detected threats."""
    try:
        db = get_db()
        db.execute("""
            INSERT INTO threats (ip_address, event_type, severity, threat_score, details)
            VALUES (?,?,?,?,?)
        """, (ip, event_type, severity, score, details))
        db.commit()
    except Exception as e:
        logger.error(f'record_threat failed: {e}')


# ══════════════════════════════════════════════════════════════════════════════
#   STARTUP
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == '__main__':
    init_db()
    logger.info('THEAN SOC starting...')

    # Production: use gunicorn or waitress, not Flask dev server
    # gunicorn -w 4 -b 0.0.0.0:5000 app:app --certfile=cert.pem --keyfile=key.pem
    # For dev only:
    app.run(
        host='127.0.0.1',  # localhost only — use nginx/cloudflare in front for public
        port=5000,
        debug=False,
        threaded=True
    )
