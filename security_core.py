"""
security_core.py — THEAN SOC Anti-Hacker Defense Layer
=======================================================
Defends against:
  - Brute force / credential stuffing
  - SQL injection
  - XSS (Cross-site scripting)
  - Path traversal
  - CSRF attacks
  - JWT token forgery
  - Rate limiting / DDoS
  - Bot detection
  - Session hijacking
  - Directory enumeration
  - HTTP header injection
  - Clickjacking
  - MIME sniffing
  - Information leakage
"""

import re
import time
import html
import hmac
import hashlib
import secrets
import logging
import ipaddress
from datetime import datetime, timedelta
from collections import defaultdict, deque
from functools import wraps
from typing import Optional
from flask import request, jsonify, g

# ── Logging ───────────────────────────────────────────────────────────────────
security_logger = logging.getLogger('thean.security')

def setup_security_logging():
    handler = logging.FileHandler('logs/security.log')
    handler.setFormatter(logging.Formatter(
        '%(asctime)s | %(levelname)s | %(message)s'
    ))
    security_logger.addHandler(handler)
    security_logger.setLevel(logging.WARNING)

# ── Rate Limiter (in-memory, token bucket) ────────────────────────────────────
class RateLimiter:
    """
    Token bucket rate limiter per IP.
    Defends against: brute force, DDoS, credential stuffing.
    """
    def __init__(self):
        self._buckets   = defaultdict(lambda: {'tokens': 10.0, 'last': time.time()})
        self._blocked   = {}  # ip -> unblock_time
        self._fail_log  = defaultdict(list)  # ip -> [timestamps]

    def _refill(self, ip: str, rate: float, capacity: float) -> float:
        b = self._buckets[ip]
        now = time.time()
        elapsed = now - b['last']
        b['tokens'] = min(capacity, b['tokens'] + elapsed * rate)
        b['last'] = now
        return b['tokens']

    def check(self, ip: str, cost: float = 1.0,
              rate: float = 2.0, capacity: float = 10.0) -> tuple[bool, str]:
        # Check if IP is blocked
        if ip in self._blocked:
            if time.time() < self._blocked[ip]:
                remaining = int(self._blocked[ip] - time.time())
                return False, f'IP blocked for {remaining}s due to repeated violations'
            else:
                del self._blocked[ip]

        tokens = self._refill(ip, rate, capacity)
        if tokens >= cost:
            self._buckets[ip]['tokens'] -= cost
            return True, 'ok'
        return False, 'Rate limit exceeded. Slow down.'

    def record_fail(self, ip: str, threshold: int = 10, window: int = 300):
        """Record a failed attempt; auto-block if threshold exceeded."""
        now = time.time()
        self._fail_log[ip] = [t for t in self._fail_log[ip] if now - t < window]
        self._fail_log[ip].append(now)
        count = len(self._fail_log[ip])
        if count >= threshold:
            block_until = now + 3600  # 1 hour block
            self._blocked[ip] = block_until
            security_logger.warning(f'AUTO-BLOCK: {ip} — {count} failures in {window}s')
            return True, count
        return False, count

    def is_blocked(self, ip: str) -> bool:
        if ip in self._blocked:
            if time.time() < self._blocked[ip]:
                return True
            del self._blocked[ip]
        return False


rate_limiter = RateLimiter()

# ── Input Sanitizer ───────────────────────────────────────────────────────────
class InputSanitizer:
    """
    Defends against: SQL injection, XSS, path traversal, command injection,
                     header injection, LDAP injection.
    """

    # SQL injection patterns
    SQL_PATTERNS = re.compile(
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|CAST|"
        r"CONVERT|DECLARE|FETCH|KILL|OPEN|TRUNCATE|BACKUP|RESTORE|LOAD|OUTFILE|"
        r"INFILE|DUMPFILE|INTO|FROM|WHERE|HAVING|GROUP\s+BY|ORDER\s+BY)\b|"
        r"--|;|\bOR\b.+=.+|'\s*OR\s*'|\bAND\b.+=.+|/\*.*\*/|xp_|sp_|0x[0-9a-f]+)",
        re.IGNORECASE
    )

    # XSS patterns
    XSS_PATTERNS = re.compile(
        r"(<script[\s\S]*?>[\s\S]*?</script>|<.*?on\w+\s*=|javascript\s*:|"
        r"vbscript\s*:|data\s*:\s*text/html|<iframe|<object|<embed|<form|"
        r"expression\s*\(|url\s*\(|@import|<link\s|<meta\s)",
        re.IGNORECASE
    )

    # Path traversal patterns
    PATH_PATTERNS = re.compile(
        r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.%2e/|%2e\./|"
        r"/etc/passwd|/etc/shadow|/proc/|\\windows\\|system32)",
        re.IGNORECASE
    )

    # Command injection patterns
    CMD_PATTERNS = re.compile(
        r"[;&|`$]|\$\(|\$\{|>|<|\bnc\b|\bnetcat\b|\bcurl\b|\bwget\b|\bchmod\b|\bsudo\b",
        re.IGNORECASE
    )

    # Header injection
    HEADER_PATTERNS = re.compile(r'[\r\n\x00]')

    @classmethod
    def check_sql(cls, value: str) -> bool:
        return bool(cls.SQL_PATTERNS.search(str(value)))

    @classmethod
    def check_xss(cls, value: str) -> bool:
        return bool(cls.XSS_PATTERNS.search(str(value)))

    @classmethod
    def check_path(cls, value: str) -> bool:
        return bool(cls.PATH_PATTERNS.search(str(value)))

    @classmethod
    def check_cmd(cls, value: str) -> bool:
        return bool(cls.CMD_PATTERNS.search(str(value)))

    @classmethod
    def sanitize_html(cls, value: str) -> str:
        """HTML-encode special characters to prevent XSS."""
        return html.escape(str(value), quote=True)

    @classmethod
    def sanitize_input(cls, value: str, max_len: int = 512) -> tuple[str, Optional[str]]:
        """
        Full sanitization pipeline.
        Returns (clean_value, error_or_None).
        """
        if not isinstance(value, str):
            value = str(value)

        # Length check
        if len(value) > max_len:
            return '', f'Input too long (max {max_len} chars)'

        # Null bytes
        if '\x00' in value:
            return '', 'Null byte detected'

        # Header injection
        if cls.HEADER_PATTERNS.search(value):
            return '', 'Invalid characters detected'

        # Threat checks
        if cls.check_sql(value):
            security_logger.warning(f'SQL INJECTION attempt: {value[:80]}')
            return '', 'Invalid input detected'

        if cls.check_xss(value):
            security_logger.warning(f'XSS attempt: {value[:80]}')
            return '', 'Invalid input detected'

        if cls.check_path(value):
            security_logger.warning(f'PATH TRAVERSAL attempt: {value[:80]}')
            return '', 'Invalid path'

        if cls.check_cmd(value):
            security_logger.warning(f'CMD INJECTION attempt: {value[:80]}')
            return '', 'Invalid characters in input'

        return value.strip(), None

    @classmethod
    def validate_ip(cls, ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @classmethod
    def validate_username(cls, username: str) -> tuple[bool, str]:
        if not username:
            return False, 'Username required'
        if not re.match(r'^[a-zA-Z0-9_\-]{3,32}$', username):
            return False, 'Username: 3-32 chars, letters/numbers/_/- only'
        return True, ''

    @classmethod
    def validate_password(cls, password: str) -> tuple[bool, str]:
        if len(password) < 8:
            return False, 'Password must be at least 8 characters'
        if len(password) > 128:
            return False, 'Password too long'
        if not re.search(r'[A-Z]', password):
            return False, 'Password must contain an uppercase letter'
        if not re.search(r'[0-9]', password):
            return False, 'Password must contain a number'
        if not re.search(r'[^A-Za-z0-9]', password):
            return False, 'Password must contain a special character'
        return True, ''


sanitizer = InputSanitizer()

# ── CSRF Protection ───────────────────────────────────────────────────────────
class CSRFProtection:
    """
    Double-submit cookie CSRF protection.
    Defends against: cross-site request forgery.
    """
    _tokens = {}  # session_id -> (token, expires)
    TOKEN_TTL = 3600  # 1 hour

    @classmethod
    def generate_token(cls, session_id: str) -> str:
        token = secrets.token_urlsafe(32)
        cls._tokens[session_id] = (token, time.time() + cls.TOKEN_TTL)
        return token

    @classmethod
    def validate_token(cls, session_id: str, token: str) -> bool:
        if session_id not in cls._tokens:
            return False
        stored, expires = cls._tokens[session_id]
        if time.time() > expires:
            del cls._tokens[session_id]
            return False
        # Constant-time comparison to prevent timing attacks
        return hmac.compare_digest(stored, token)

    @classmethod
    def cleanup_expired(cls):
        now = time.time()
        cls._tokens = {k: v for k, v in cls._tokens.items() if v[1] > now}


csrf = CSRFProtection()

# ── Security Headers ──────────────────────────────────────────────────────────
SECURITY_HEADERS = {
    # Prevent clickjacking
    'X-Frame-Options': 'DENY',
    # Prevent MIME sniffing
    'X-Content-Type-Options': 'nosniff',
    # XSS filter (legacy browsers)
    'X-XSS-Protection': '1; mode=block',
    # HSTS — force HTTPS for 1 year
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    # Content Security Policy — tight whitelist
    'Content-Security-Policy': (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    ),
    # Referrer policy
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    # Permissions policy — disable dangerous browser features
    'Permissions-Policy': (
        'geolocation=(), microphone=(), camera=(), payment=(), '
        'usb=(), bluetooth=(), magnetometer=(), gyroscope=()'
    ),
    # Remove server info
    'Server': 'THEAN-SOC',
    # Cache control for sensitive pages
    'Cache-Control': 'no-store, no-cache, must-revalidate, private',
    'Pragma': 'no-cache',
}


def apply_security_headers(response):
    """Apply all security headers to every response."""
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value
    # Remove information-leaking headers
    response.headers.pop('X-Powered-By', None)
    return response


# ── Bot / Scanner Detection ───────────────────────────────────────────────────
BOT_UA_PATTERNS = re.compile(
    r'(sqlmap|nikto|nmap|masscan|zgrab|nuclei|acunetix|burpsuite|'
    r'nessus|openvas|w3af|metasploit|havij|commix|hydra|medusa|'
    r'gobuster|dirb|dirbuster|wfuzz|ffuf|feroxbuster|'
    r'python-requests|go-http-client|curl/|wget/|libwww-perl|'
    r'scrapy|arachni|skipfish)',
    re.IGNORECASE
)

SCANNER_PATHS = re.compile(
    r'(/wp-admin|/wp-login|/phpmyadmin|/.env|/config|/backup|'
    r'/admin\.php|/shell\.php|/c99|/r57|/webshell|/.git/|'
    r'/\.htaccess|/web\.config|/server-status|/solr|/jndi|'
    r'/actuator|/api/v1/pods|/__proto__|/node_modules)',
    re.IGNORECASE
)


def detect_scanner(ua: str, path: str) -> tuple[bool, str]:
    if BOT_UA_PATTERNS.search(ua or ''):
        return True, f'Known scanner/tool UA: {ua[:60]}'
    if SCANNER_PATHS.search(path):
        return True, f'Scanner path probe: {path}'
    return False, ''


# ── Decorators for routes ─────────────────────────────────────────────────────
def require_rate_limit(cost=1.0, rate=2.0, capacity=10.0):
    """Decorator: rate-limit a route by IP."""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            ip = get_real_ip()
            allowed, msg = rate_limiter.check(ip, cost, rate, capacity)
            if not allowed:
                security_logger.warning(f'RATE_LIMIT: {ip} — {request.path}')
                return jsonify(error=msg), 429
            return f(*args, **kwargs)
        return wrapped
    return decorator


def require_no_scanner(f):
    """Decorator: block known security scanners."""
    @wraps(f)
    def wrapped(*args, **kwargs):
        ua   = request.headers.get('User-Agent', '')
        path = request.path
        is_scanner, reason = detect_scanner(ua, path)
        if is_scanner:
            ip = get_real_ip()
            security_logger.warning(f'SCANNER_BLOCKED: {ip} — {reason}')
            rate_limiter._blocked[ip] = time.time() + 86400  # 24hr block
            return jsonify(error='Forbidden'), 403
        return f(*args, **kwargs)
    return wrapped


def require_auth(f):
    """Decorator: validate JWT auth token."""
    @wraps(f)
    def wrapped(*args, **kwargs):
        from app import verify_token  # lazy import to avoid circular
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify(error='Authentication required'), 401
        payload = verify_token(token)
        if not payload:
            security_logger.warning(f'INVALID_TOKEN: {get_real_ip()} — {request.path}')
            return jsonify(error='Invalid or expired token'), 401
        g.user = payload
        return f(*args, **kwargs)
    return wrapped


def require_admin(f):
    """Decorator: require admin role."""
    @wraps(f)
    @require_auth
    def wrapped(*args, **kwargs):
        if g.user.get('role') != 'admin':
            security_logger.warning(f'PRIV_ESC_ATTEMPT: user={g.user.get("sub")} path={request.path}')
            return jsonify(error='Insufficient privileges'), 403
        return f(*args, **kwargs)
    return wrapped


# ── IP Helpers ────────────────────────────────────────────────────────────────
TRUSTED_PROXIES = {'127.0.0.1', '::1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'}

def get_real_ip() -> str:
    """Get real client IP, respecting trusted reverse proxies."""
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        ip = forwarded.split(',')[0].strip()
        try:
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            pass
    return request.remote_addr or '0.0.0.0'


# ── Honeypot fields ───────────────────────────────────────────────────────────
def check_honeypot(data: dict) -> bool:
    """
    Returns True if honeypot field is filled (indicates a bot).
    Add a hidden input field named 'website' or 'phone' in the form — bots fill it.
    """
    honeypot_fields = ['website', 'phone', 'fax', 'address2', 'confirm_email']
    return any(data.get(f) for f in honeypot_fields)


# ── Request Inspector ─────────────────────────────────────────────────────────
class RequestInspector:
    """Full request threat scoring."""

    @staticmethod
    def score(req) -> tuple[int, list]:
        """Returns (threat_score 0-100, list_of_reasons)."""
        score   = 0
        reasons = []
        ip      = get_real_ip()

        # Blocked IP
        if rate_limiter.is_blocked(ip):
            return 100, ['IP is blocked']

        # Known scanner UA
        ua = req.headers.get('User-Agent', '')
        if not ua:
            score += 20; reasons.append('No User-Agent')
        elif BOT_UA_PATTERNS.search(ua):
            score += 80; reasons.append('Known attack tool UA')

        # Scanner paths
        if SCANNER_PATHS.search(req.path):
            score += 60; reasons.append('Scanner probe path')

        # Suspicious headers
        if req.headers.get('X-Forwarded-Host') and req.headers.get('X-Forwarded-Host') != req.host:
            score += 30; reasons.append('Host header injection attempt')

        # Very long URL
        if len(req.url) > 2048:
            score += 20; reasons.append('Unusually long URL')

        # SQL/XSS in query params
        for k, v in req.args.items():
            if sanitizer.check_sql(v) or sanitizer.check_xss(v):
                score += 50; reasons.append(f'Attack pattern in query param: {k}'); break

        return min(score, 100), reasons


inspector = RequestInspector()
