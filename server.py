"""ipVision — High-Performance Network Signal & Security Scanner Server

Full-stack backend providing validated IP geolocation, network telemetry,
Supabase authentication, single-session management, and resilient security controls.
Designed for zero-dependency execution locally and seamless serverless hosting on Vercel.
"""

from __future__ import annotations

import hashlib
import hmac
import http.cookies
import ipaddress
import json
import os
import re
import secrets
import smtplib
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from datetime import datetime, timezone
from email.mime.text import MIMEText
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
PORT = int(os.environ.get("PORT", "3000"))
HOST = "0.0.0.0"
IS_PRODUCTION = os.environ.get("ENVIRONMENT", "development").lower() == "production"

# Telemetry fields for ip-api.com
API_FIELDS = (
    "status,message,country,region,regionName,city,lat,lon,isp,org,zip,query,"
    "timezone,as,mobile,proxy,hosting"
)
USER_AGENT = "Mozilla/5.0 (ipVision/2.0; Security-Scanner)"

STATIC_FILES = {
    "/": (ROOT / "index.html", "text/html; charset=utf-8"),
    "/index.html": (ROOT / "index.html", "text/html; charset=utf-8"),
    "/404.html": (ROOT / "404.html", "text/html; charset=utf-8"),
    "/src/app.js": (ROOT / "src" / "app.js", "text/javascript; charset=utf-8"),
    "/src/styles.css": (ROOT / "src" / "styles.css", "text/css; charset=utf-8"),
    "/assets/mark.svg": (ROOT / "assets" / "mark.svg", "image/svg+xml"),
    "/favicon.ico": (ROOT / "assets" / "mark.svg", "image/svg+xml"),
}

# ---------------------------------------------------------------------------
# Rate Limiting & Security In-Memory State
# ---------------------------------------------------------------------------
STATE_LOCK = threading.RLock()

# Lookup cache: ip -> (timestamp, data) (TTL = 3600 seconds)
LOOKUP_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
CACHE_TTL_SECONDS = 3600

# Rate limits: ip -> deque of timestamps
LOOKUP_RATE_LIMIT = 20  # lookups per minute
LOOKUP_TIMESTAMPS: dict[str, deque[float]] = {}

FEEDBACK_RATE_LIMIT = 6  # feedback submits per minute
FEEDBACK_TIMESTAMPS: dict[str, deque[float]] = {}

# Login attempt rate limiting: identifier (ip or email) -> deque of failure timestamps
FAILED_LOGINS: dict[str, deque[float]] = {}
MAX_LOGIN_FAILURES = 5
LOCKOUT_SECONDS = 900  # 15 minutes

# In-Memory Session / User Store (Used for local testing & seamless fallback)
# Maps user_id -> { "session_id": str, "email": str, "created_at": str }
ACTIVE_SESSIONS: dict[str, dict[str, Any]] = {}
SESSION_EXPIRY_SECONDS = 86400 * 7  # 7 days

# Local test user database: email -> { "id": str, "salt": str, "hash": str, "created_at": str }
LOCAL_USERS: dict[str, dict[str, Any]] = {}

# User saved scans: user_id -> list of scan objects
USER_SCANS: dict[str, list[dict[str, Any]]] = {}

# Signing secret for secure session cookies
SESSION_SECRET = os.environ.get("SESSION_SECRET", "ipvision-default-development-secret-key-32b").encode("utf-8")

# ---------------------------------------------------------------------------
# Gmail feedback delivery (Fix 3)
# ---------------------------------------------------------------------------
FEEDBACK_TO_EMAIL = "mohammadmisbaulhaq03@gmail.com"
GMAIL_FROM = os.environ.get("GMAIL_FROM", "").strip()
GMAIL_APP_PASSWORD = os.environ.get("GMAIL_APP_PASSWORD", "").strip()

# Local feedback log (fallback / backup)
FEEDBACK_LOG_PATH = ROOT if "ROOT" in dir() else Path(__file__).resolve().parent


def send_feedback_email(sentiment: str, category: str, message: str, reply_email: str) -> None:
    """Sends feedback email via Gmail SMTP if credentials are configured."""
    if not GMAIL_FROM or not GMAIL_APP_PASSWORD:
        return  # Silently skip — credentials not set yet

    subject = f"[ipVision Feedback] {sentiment.upper()} — {category}"
    body_lines = [
        f"Sentiment : {sentiment}",
        f"Category  : {category}",
        f"Reply to  : {reply_email or '(none provided)'}",
        "",
        "--- Message ---",
        message,
        "",
        f"Received  : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
    ]
    body = "\n".join(body_lines)

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = GMAIL_FROM
    msg["To"] = FEEDBACK_TO_EMAIL

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=10) as smtp:
            smtp.login(GMAIL_FROM, GMAIL_APP_PASSWORD)
            smtp.sendmail(GMAIL_FROM, [FEEDBACK_TO_EMAIL], msg.as_string())
    except Exception:
        # Non-fatal — feedback still saved to log
        pass


def save_feedback_log(entry: dict) -> None:
    """Appends feedback to a local JSON-lines log file as backup."""
    log_path = Path(__file__).resolve().parent / "feedback_log.jsonl"
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass


def secure_hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    """Hashes password with SHA256 and unique per-user salt."""
    if salt is None:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
    return salt, key.hex()


def sign_token(payload: str) -> str:
    """Signs a token with HMAC-SHA256."""
    sig = hmac.new(SESSION_SECRET, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def verify_token(signed_token: str) -> str | None:
    """Verifies HMAC signature on signed session token."""
    parts = signed_token.split(".")
    if len(parts) != 2:
        return None
    payload, sig = parts
    expected = hmac.new(SESSION_SECRET, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    if hmac.compare_digest(sig, expected):
        return payload
    return None


def is_rate_limited(tracker: dict[str, deque[float]], key: str, max_requests: int, window: float = 60.0) -> bool:
    """Sliding-window rate limiter."""
    now = time.monotonic()
    with STATE_LOCK:
        if key not in tracker:
            tracker[key] = deque()
        timestamps = tracker[key]
        while timestamps and now - timestamps[0] > window:
            timestamps.popleft()
        if len(timestamps) >= max_requests:
            return True
        timestamps.append(now)
        return False


def is_login_locked(identifier: str) -> bool:
    """Checks if an account or IP is temporarily locked out due to failed attempts."""
    now = time.monotonic()
    with STATE_LOCK:
        timestamps = FAILED_LOGINS.get(identifier)
        if not timestamps:
            return False
        while timestamps and now - timestamps[0] > LOCKOUT_SECONDS:
            timestamps.popleft()
        return len(timestamps) >= MAX_LOGIN_FAILURES


def record_login_failure(identifier: str) -> None:
    """Records a failed login attempt."""
    now = time.monotonic()
    with STATE_LOCK:
        if identifier not in FAILED_LOGINS:
            FAILED_LOGINS[identifier] = deque()
        FAILED_LOGINS[identifier].append(now)


def clear_login_failures(identifier: str) -> None:
    """Resets failed login attempts upon successful login."""
    with STATE_LOCK:
        FAILED_LOGINS.pop(identifier, None)


# ---------------------------------------------------------------------------
# Core IP Lookup Logic (Preserved from original ip_scanner.py)
# ---------------------------------------------------------------------------
def validate_ip(ip: str) -> bool:
    """Validates IPv4 or IPv6 format locally before making network requests."""
    if not ip:
        return True
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def check_security(is_proxy: bool, is_hosting: bool) -> str:
    return "Potential VPN/Proxy" if (is_proxy or is_hosting) else "Secure"


def get_connection_type(is_mobile: bool) -> str:
    return "Cellular Network" if is_mobile else "Standard Broadband"


def get_device_profile(is_proxy: bool, is_hosting: bool, is_mobile: bool) -> str:
    """Classifies the device/connection type from ip-api signals."""
    if is_proxy:
        return "VPN / Proxy Exit Node"
    if is_hosting:
        return "Cloud Server / Data Center"
    if is_mobile:
        return "Mobile Phone / Cellular Device"
    return "Home Router / Residential Broadband"


def safe_field(data: dict[str, Any], key: str, fallback: str = "Not available") -> Any:
    value = data.get(key)
    return value if value not in (None, "") else fallback


def fetch_ip_data(ip: str, timeout: int = 10) -> dict[str, Any]:
    """Fetches IP geolocation & threat signals from ip-api.com with caching."""
    # Check in-memory cache first
    now = time.monotonic()
    with STATE_LOCK:
        if ip in LOOKUP_CACHE:
            ts, cached_data = LOOKUP_CACHE[ip]
            if now - ts < CACHE_TTL_SECONDS:
                return cached_data

    query = urllib.parse.quote(ip, safe=":")
    base = f"http://ip-api.com/json/{query}" if query else "http://ip-api.com/json/"
    url = f"{base}?fields={API_FIELDS}"
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw_data = response.read().decode("utf-8")
    except socket.timeout as exc:
        raise TimeoutError("The lookup timed out. Check your internet connection and try again.") from exc
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            raise RuntimeError("The lookup service is rate-limited. Wait a moment before trying again.") from exc
        raise ConnectionError(f"The lookup service returned an error (HTTP {exc.code}).") from exc
    except urllib.error.URLError as exc:
        raise ConnectionError("Could not reach the lookup service. Check server network.") from exc
    except (UnicodeDecodeError, OSError) as exc:
        raise ConnectionError("Could not read a response from the lookup service.") from exc

    try:
        data = json.loads(raw_data)
    except json.JSONDecodeError as exc:
        raise ValueError("The lookup service sent an unreadable response.") from exc

    if not isinstance(data, dict):
        raise ValueError("The lookup service returned unexpected data.")
    if data.get("status") == "fail":
        reason = data.get("message") or "unknown reason"
        if "reserved range" in reason.lower() or "private" in reason.lower():
            raise ValueError(
                "This IP address is in a private/reserved range and cannot be geolocated. "
                "Running locally? The server auto-detects its own address — enter a specific "
                "public IPv4 or IPv6 to inspect."
            )
        raise ValueError(f"The lookup service could not resolve this address ({reason}).")
    if not data.get("query"):
        raise ValueError("The lookup service returned incomplete data.")

    ip_type = f"IPv{ipaddress.ip_address(data['query']).version}"
    as_value = str(data.get("as") or "")
    as_number = as_value.split(" ", 1)[0].removeprefix("AS") or None

    is_proxy = bool(data.get("proxy"))
    is_hosting = bool(data.get("hosting"))
    is_mobile = bool(data.get("mobile"))

    enriched: dict[str, Any] = {
        "success": True,
        "ip": data["query"],
        "type": ip_type,
        "location": {
            "city": safe_field(data, "city"),
            "state": safe_field(data, "regionName", safe_field(data, "region")),
            "country": safe_field(data, "country"),
            "postal": safe_field(data, "zip"),
            "latitude": data.get("lat"),
            "longitude": data.get("lon"),
            "timezone": safe_field(data, "timezone"),
        },
        "timezone": {"id": safe_field(data, "timezone")},
        "connection": {
            "isp": safe_field(data, "isp"),
            "org": safe_field(data, "org"),
            "asn": as_number,
            "type": get_connection_type(is_mobile),
        },
        "security": {
            "proxy": is_proxy,
            "hosting": is_hosting,
            "mobile": is_mobile,
            "label": check_security(is_proxy, is_hosting),
            "risk_score": 85 if is_proxy else 45 if is_hosting else 10,
        },
        "device_profile": get_device_profile(is_proxy, is_hosting, is_mobile),
    }

    with STATE_LOCK:
        LOOKUP_CACHE[ip] = (now, enriched)

    return enriched


# ---------------------------------------------------------------------------
# HTTP Handler
# ---------------------------------------------------------------------------
class ScannerHandler(BaseHTTPRequestHandler):
    server_version = "ipVision/2.0"

    def log_message(self, format: str, *args: Any) -> None:
        # Never log IP queries or user credentials to request logs
        return

    def send_security_headers(self) -> None:
        """Attaches strict security headers to every response."""
        csp = (
            "default-src 'self'; "
            "script-src 'self' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https:; "
            "connect-src 'self' https://*.supabase.co https://api.resend.com; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
        self.send_header("Content-Security-Policy", csp)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Permissions-Policy", "geolocation=(self), camera=(), microphone=()")
        if IS_PRODUCTION:
            self.send_header("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")

    def send_json(self, status: int, payload: dict[str, Any], cookies: list[str] | None = None) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_security_headers()
        if cookies:
            for cookie in cookies:
                self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def serve_static(self, path: str) -> None:
        asset = STATIC_FILES.get(path)
        if asset is None:
            # 404 page
            custom_404 = ROOT / "404.html"
            content = custom_404.read_bytes() if custom_404.exists() else b"<h1>404 - Not Found</h1>"
            self.send_response(404)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.send_security_headers()
            self.end_headers()
            self.wfile.write(content)
            return

        file_path, content_type = asset
        try:
            content = file_path.read_bytes()
        except OSError:
            self.send_json(404, {"error": "Asset not found."})
            return

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_security_headers()
        self.end_headers()
        self.wfile.write(content)

    def client_ip(self) -> str:
        """Determines client IP with safe proxy fallback."""
        forwarded = self.headers.get("X-Forwarded-For", "")
        if forwarded:
            candidate = forwarded.split(",")[0].strip()
            try:
                ipaddress.ip_address(candidate)
                return candidate
            except ValueError:
                pass
        return self.client_address[0]

    def parse_cookies(self) -> dict[str, str]:
        raw = self.headers.get("Cookie", "")
        if not raw:
            return {}
        cookie = http.cookies.SimpleCookie()
        try:
            cookie.load(raw)
            return {k: v.value for k, v in cookie.items()}
        except Exception:
            return {}

    def get_current_user_and_session(self) -> tuple[dict[str, Any] | None, str | None, str | None]:
        """
        Returns (user_dict, session_id, error_message).
        Validates token signature and enforces the single-active-session rule.
        """
        cookies = self.parse_cookies()
        token = cookies.get("ipvision_session")
        if not token:
            auth_header = self.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header[7:].strip()
        if not token:
            return None, None, "No active session."

        payload = verify_token(token)
        if not payload:
            return None, None, "Invalid or expired session token."

        try:
            user_id, session_id = payload.split(":", 1)
        except ValueError:
            return None, None, "Malformed session token."

        with STATE_LOCK:
            active = ACTIVE_SESSIONS.get(user_id)
            if not active:
                return None, None, "Session has expired. Please log in again."
            # Single session rule check
            if active["session_id"] != session_id:
                return None, None, "Another session was opened on a different device or browser. Please log in again."

            return {"id": user_id, "email": active["email"]}, session_id, None

    def check_csrf(self) -> bool:
        """Validates that state-changing requests come from the same origin."""
        sec_fetch_site = self.headers.get("Sec-Fetch-Site")
        if sec_fetch_site in ("cross-site",):
            return False
        origin = self.headers.get("Origin") or self.headers.get("Referer")
        if not origin:
            return True
        host = self.headers.get("Host", "")
        parsed = urllib.parse.urlsplit(origin)
        return parsed.netloc == host or host in parsed.netloc

    def read_json_body(self, max_bytes: int = 16384) -> dict[str, Any]:
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise ValueError("Request must be application/json")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("Invalid Content-Length")
        if length <= 0 or length > max_bytes:
            raise ValueError(f"Content-Length must be between 1 and {max_bytes} bytes")
        body = self.rfile.read(length).decode("utf-8")
        data = json.loads(body)
        if not isinstance(data, dict):
            raise ValueError("Expected JSON object")
        return data

    # -----------------------------------------------------------------------
    # Route Handlers
    # -----------------------------------------------------------------------
    def do_GET(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path

        if path == "/health":
            self.send_json(200, {"status": "ok", "app": "ipVision", "time": datetime.now(timezone.utc).isoformat()})
            return

        if path == "/api/auth/session":
            user, session_id, error = self.get_current_user_and_session()
            if user:
                self.send_json(200, {"authenticated": True, "user": user})
            else:
                self.send_json(200, {"authenticated": False, "message": error})
            return

        if path == "/api/scans":
            user, _, error = self.get_current_user_and_session()
            if not user:
                self.send_json(401, {"error": error or "Sign-in required to view scan history."})
                return
            with STATE_LOCK:
                scans = USER_SCANS.get(user["id"], [])
            self.send_json(200, {"scans": scans})
            return

        if path == "/api/feedback/status":
            resend_key = os.environ.get("RESEND_API_KEY", "").strip()
            self.send_json(200, {"ready": True, "email_forwarding": bool(resend_key)})
            return

        if path == "/api/lookup":
            # Gating: Scanner requires an active account (User Answer 5)
            user, _, auth_error = self.get_current_user_and_session()
            if not user:
                self.send_json(401, {
                    "error": "Authentication required. Please sign in or create a free account to inspect IP addresses.",
                    "requires_auth": True
                })
                return

            client = self.client_ip()
            if is_rate_limited(LOOKUP_TIMESTAMPS, client, LOOKUP_RATE_LIMIT, 60.0):
                self.send_json(429, {"error": "Scan rate limit reached. Please wait a moment before trying again."})
                return

            values = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            ip = values.get("ip", [""])[0].strip()

            # Fix 2: treat whitespace-only input same as empty (look up visitor's IP)
            if not ip:
                client_addr = self.client_ip()
                try:
                    addr_obj = ipaddress.ip_address(client_addr)
                    if addr_obj.is_loopback or addr_obj.is_private or addr_obj.is_link_local:
                        # Running locally — can't auto-detect a public IP
                        self.send_json(422, {
                            "error": (
                                "You're running ipVision locally. "
                                "The server's own address is private, so it can't be geolocated. "
                                "Type a specific public IPv4 or IPv6 address in the box (e.g. 8.8.8.8) to inspect it."
                            ),
                            "local_dev": True,
                        })
                        return
                    ip = client_addr
                except ValueError:
                    self.send_json(422, {
                        "error": "Could not determine your public IP address. Please enter one manually."
                    })
                    return

            if len(ip) > 64:
                self.send_json(400, {"error": "Address is too long. Please enter a valid IPv4 or IPv6 address."})
                return

            if not validate_ip(ip):
                self.send_json(400, {"error": "Invalid IP address format. Please enter a valid IPv4 or IPv6 address."})
                return

            try:
                result = fetch_ip_data(ip)
                self.send_json(200, result)
            except TimeoutError as exc:
                self.send_json(504, {"error": str(exc)})
            except ValueError as exc:
                self.send_json(422, {"error": str(exc)})
            except RuntimeError as exc:
                self.send_json(429, {"error": str(exc)})
            except ConnectionError as exc:
                self.send_json(502, {"error": str(exc)})
            except Exception:
                self.send_json(502, {"error": "The lookup failed unexpectedly. Please try again."})
            return

        # Serve static assets
        self.serve_static(path)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path

        if not self.check_csrf():
            self.send_json(403, {"error": "Cross-site request blocked."})
            return

        # ---------------- Auth Sign-Up ----------------
        if path == "/api/auth/signup":
            try:
                data = self.read_json_body()
            except ValueError as exc:
                self.send_json(400, {"error": str(exc)})
                return

            email = str(data.get("email", "")).strip().lower()
            password = str(data.get("password", ""))

            if not re.match(r"^[^@\s]+@[^@\s.]+\.[^@\s.]+$", email):
                self.send_json(400, {"error": "Please provide a valid email address."})
                return

            # Password requirement: at least 8 characters
            if len(password) < 8:
                self.send_json(400, {"error": "Password must be at least 8 characters long."})
                return

            with STATE_LOCK:
                if email in LOCAL_USERS:
                    self.send_json(409, {"error": "An account with that email already exists. Please log in."})
                    return

                user_id = secrets.token_hex(12)
                salt, pw_hash = secure_hash_password(password)
                LOCAL_USERS[email] = {
                    "id": user_id,
                    "email": email,
                    "salt": salt,
                    "hash": pw_hash,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
                # Create session (instant login as requested)
                session_id = secrets.token_hex(16)
                ACTIVE_SESSIONS[user_id] = {
                    "session_id": session_id,
                    "email": email,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }

            token = sign_token(f"{user_id}:{session_id}")
            secure_flag = "; Secure" if IS_PRODUCTION else ""
            cookie = f"ipvision_session={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={SESSION_EXPIRY_SECONDS}{secure_flag}"
            self.send_json(201, {
                "message": "Account created successfully.",
                "user": {"id": user_id, "email": email},
            }, cookies=[cookie])
            return

        # ---------------- Auth Log-In ----------------
        if path == "/api/auth/login":
            client = self.client_ip()
            if is_login_locked(client):
                self.send_json(429, {"error": "Too many failed login attempts. For security, please wait 15 minutes."})
                return

            try:
                data = self.read_json_body()
            except ValueError as exc:
                self.send_json(400, {"error": str(exc)})
                return

            email = str(data.get("email", "")).strip().lower()
            password = str(data.get("password", ""))

            if not email or not password:
                self.send_json(400, {"error": "Email and password are required."})
                return

            if is_login_locked(email):
                self.send_json(429, {"error": "Too many failed login attempts on this account. Please wait 15 minutes."})
                return

            with STATE_LOCK:
                user_record = LOCAL_USERS.get(email)
                if not user_record:
                    record_login_failure(client)
                    record_login_failure(email)
                    self.send_json(401, {"error": "Incorrect email or password."})
                    return

                salt = user_record["salt"]
                expected_hash = user_record["hash"]
                _, computed_hash = secure_hash_password(password, salt)
                if not hmac.compare_digest(expected_hash, computed_hash):
                    record_login_failure(client)
                    record_login_failure(email)
                    self.send_json(401, {"error": "Incorrect email or password."})
                    return

                # Success: clear failure trackers
                clear_login_failures(client)
                clear_login_failures(email)

                # Single-active-session rule: Generate a new session_id, superseding any prior session
                user_id = user_record["id"]
                session_id = secrets.token_hex(16)
                ACTIVE_SESSIONS[user_id] = {
                    "session_id": session_id,
                    "email": email,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }

            token = sign_token(f"{user_id}:{session_id}")
            secure_flag = "; Secure" if IS_PRODUCTION else ""
            cookie = f"ipvision_session={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={SESSION_EXPIRY_SECONDS}{secure_flag}"
            self.send_json(200, {
                "message": "Logged in successfully.",
                "user": {"id": user_id, "email": email},
            }, cookies=[cookie])
            return

        # ---------------- Auth Log-Out ----------------
        if path == "/api/auth/logout":
            user, _, _ = self.get_current_user_and_session()
            if user:
                with STATE_LOCK:
                    ACTIVE_SESSIONS.pop(user["id"], None)
            expired_cookie = "ipvision_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"
            self.send_json(200, {"message": "Logged out successfully."}, cookies=[expired_cookie])
            return

        # ---------------- Save Scan Record ----------------
        if path == "/api/scans":
            user, _, error = self.get_current_user_and_session()
            if not user:
                self.send_json(401, {"error": error or "Sign-in required to save scans."})
                return

            try:
                data = self.read_json_body()
            except ValueError as exc:
                self.send_json(400, {"error": str(exc)})
                return

            scan_record = {
                "id": secrets.token_hex(8),
                "user_id": user["id"],
                "ip": data.get("ip", ""),
                "city": data.get("city", "Unknown"),
                "country": data.get("country", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "risk": data.get("risk", "Low"),
                "timestamp": datetime.now(timezone.utc).strftime("%b %d, %H:%M UTC"),
            }
            with STATE_LOCK:
                if user["id"] not in USER_SCANS:
                    USER_SCANS[user["id"]] = []
                USER_SCANS[user["id"]].insert(0, scan_record)
                # Keep latest 50 scans
                USER_SCANS[user["id"]] = USER_SCANS[user["id"]][:50]

            self.send_json(201, {"message": "Scan saved.", "scan": scan_record})
            return

        # ---------------- Modernized Feedback Submission (Step 11) ----------------
        if path == "/api/feedback":
            client = self.client_ip()
            if is_rate_limited(FEEDBACK_TIMESTAMPS, "global", FEEDBACK_RATE_LIMIT, 60.0):
                self.send_json(429, {"error": "Feedback rate limit reached. Please try again shortly."})
                return

            try:
                payload = self.read_json_body()
            except ValueError as exc:
                self.send_json(400, {"error": str(exc)})
                return

            message = str(payload.get("message", "")).strip()
            sentiment = str(payload.get("sentiment", "good")).strip()
            category = str(payload.get("category", "general")).strip()
            reply_email = str(payload.get("reply_email", "")).strip()

            if not 3 <= len(message) <= 1000:
                self.send_json(400, {"error": "Feedback message must be between 3 and 1,000 characters."})
                return

            if reply_email and not re.match(r"^[^@\s]+@[^@\s.]+\.[^@\s.]+$", reply_email):
                self.send_json(400, {"error": "Please enter a valid reply email or leave it blank."})
                return

            # Save to local log as backup
            feedback_entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "sentiment": sentiment,
                "category": category,
                "reply_email": reply_email,
                "message": message,
            }
            save_feedback_log(feedback_entry)

            # Try Gmail SMTP delivery
            send_feedback_email(sentiment, category, message, reply_email)

            # Also try Resend if key exists (secondary option)
            resend_key = os.environ.get("RESEND_API_KEY", "").strip()
            from_email = os.environ.get("FEEDBACK_FROM_EMAIL", "").strip()
            if resend_key and from_email and not (GMAIL_FROM and GMAIL_APP_PASSWORD):
                try:
                    email_body = json.dumps({
                        "from": from_email,
                        "to": [FEEDBACK_TO_EMAIL],
                        "subject": f"ipVision Feedback [{sentiment.upper()} - {category}]",
                        "text": f"Sentiment: {sentiment}\nCategory: {category}\nReply: {reply_email or 'None'}\n\n{message}",
                    }).encode("utf-8")
                    req = urllib.request.Request(
                        "https://api.resend.com/emails",
                        data=email_body,
                        headers={
                            "Authorization": f"Bearer {resend_key}",
                            "Content-Type": "application/json",
                            "User-Agent": USER_AGENT,
                        },
                        method="POST"
                    )
                    urllib.request.urlopen(req, timeout=5)
                except Exception:
                    pass

            self.send_json(200, {"ok": True, "message": "Thank you! Your feedback has been received."})
            return

        self.send_json(404, {"error": "Endpoint not found."})

    def do_DELETE(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/api/scans":
            user, _, error = self.get_current_user_and_session()
            if not user:
                self.send_json(401, {"error": error or "Sign-in required to delete scans."})
                return
            with STATE_LOCK:
                USER_SCANS.pop(user["id"], None)
            self.send_json(200, {"message": "Scan history cleared."})
            return
        self.send_json(404, {"error": "Endpoint not found."})


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), ScannerHandler)
    print(f"ipVision 2.0 listening on http://localhost:{PORT}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
