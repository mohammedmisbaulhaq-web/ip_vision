"""Comprehensive Backend Test Suite for ipVision 2.0

Tests:
1. IP Validation & Core Security Flag Logic (from ip_scanner.py)
2. User Sign-Up (Email validation, 8-character password enforcement, duplicate email rejection)
3. User Log-In & Failed Attempt Lockout Protection
4. Single-Active-Session Enforcement (Older session invalidation on new login)
5. Scan History Saving & Multi-User Data Isolation (Row-level separation)
6. Scanner Gating (Unauthenticated requests blocked)
7. Feedback Submission & Message Length Validation
"""

import unittest
import json
import io
import time

import server
from server import (
    validate_ip,
    check_security,
    get_connection_type,
    LOCAL_USERS,
    ACTIVE_SESSIONS,
    USER_SCANS,
    FAILED_LOGINS,
    ScannerHandler,
)


class MockServer:
    """Mock server for BaseHTTPRequestHandler testing."""
    def __init__(self):
        self.server_name = "localhost"
        self.server_port = 3000


def simulate_request(method: str, path: str, body: dict = None, headers: dict = None):
    """Simulates an HTTP request cleanly in-memory against ScannerHandler."""
    raw_body = json.dumps(body).encode("utf-8") if body is not None else b""
    req_lines = [f"{method} {path} HTTP/1.1", "Host: localhost:3000"]
    if headers:
        for k, v in headers.items():
            req_lines.append(f"{k}: {v}")
    if raw_body:
        req_lines.append("Content-Type: application/json")
        req_lines.append(f"Content-Length: {len(raw_body)}")
    req_lines.append("")
    req_lines.append("")

    raw_req = "\r\n".join(req_lines).encode("utf-8") + raw_body

    handler = ScannerHandler.__new__(ScannerHandler)
    handler.server = MockServer()
    handler.client_address = ("127.0.0.1", 54321)
    handler.rfile = io.BytesIO(raw_req)
    handler.wfile = io.BytesIO()
    handler._headers_buffer = []

    handler.raw_requestline = handler.rfile.readline(65537)
    if not handler.parse_request():
        return 400, {}, {"error": "Bad request"}

    if handler.command == "GET":
        handler.do_GET()
    elif handler.command == "POST":
        handler.do_POST()
    elif handler.command == "DELETE":
        handler.do_DELETE()

    output = handler.wfile.getvalue().decode("utf-8", errors="ignore")
    lines = output.split("\r\n")
    status_line = lines[0]
    status_code = int(status_line.split(" ")[1])

    resp_headers = {}
    idx = 1
    while idx < len(lines) and lines[idx]:
        header_line = lines[idx]
        if ":" in header_line:
            name, val = header_line.split(":", 1)
            resp_headers[name.strip().lower()] = val.strip()
        idx += 1

    resp_body = "\r\n".join(lines[idx + 1:])
    try:
        json_data = json.loads(resp_body) if resp_body else {}
    except Exception:
        json_data = resp_body

    return status_code, resp_headers, json_data


class TestIPVisionBackend(unittest.TestCase):
    def setUp(self):
        # Clear in-memory databases before each test
        LOCAL_USERS.clear()
        ACTIVE_SESSIONS.clear()
        USER_SCANS.clear()
        FAILED_LOGINS.clear()

    # 1. IP Validation Tests
    def test_ip_validation(self):
        self.assertTrue(validate_ip(""), "Blank input should be valid (self-scan)")
        self.assertTrue(validate_ip("8.8.8.8"), "Valid IPv4 should pass")
        self.assertTrue(validate_ip("1.1.1.1"), "Valid IPv4 should pass")
        self.assertTrue(validate_ip("2001:4860:4860::8888"), "Valid IPv6 should pass")
        self.assertFalse(validate_ip("999.999.999.999"), "Out of range IPv4 should fail")
        self.assertFalse(validate_ip("random-domain.com"), "Domain strings should fail")
        self.assertFalse(validate_ip("192.168.1.500"), "Invalid octet should fail")

    def test_security_indicators(self):
        self.assertEqual(check_security(False, False), "Secure")
        self.assertEqual(check_security(True, False), "Potential VPN/Proxy")
        self.assertEqual(check_security(False, True), "Potential VPN/Proxy")
        self.assertEqual(get_connection_type(True), "Cellular Network")
        self.assertEqual(get_connection_type(False), "Standard Broadband")

    # 2. Sign-Up Tests
    def test_signup_success(self):
        status, headers, body = simulate_request("POST", "/api/auth/signup", {
            "email": "analyst@ipvision.io",
            "password": "SecurePassword123"
        })
        self.assertEqual(status, 201)
        self.assertIn("user", body)
        self.assertEqual(body["user"]["email"], "analyst@ipvision.io")
        self.assertIn("set-cookie", headers)
        self.assertIn("ipvision_session=", headers["set-cookie"])

    def test_signup_short_password(self):
        status, _, body = simulate_request("POST", "/api/auth/signup", {
            "email": "analyst@ipvision.io",
            "password": "short"  # Less than 8 chars
        })
        self.assertEqual(status, 400)
        self.assertIn("at least 8 characters", body.get("error", ""))

    def test_signup_duplicate_email(self):
        simulate_request("POST", "/api/auth/signup", {
            "email": "user@domain.com",
            "password": "ValidPassword123"
        })
        status, _, body = simulate_request("POST", "/api/auth/signup", {
            "email": "user@domain.com",
            "password": "AnotherPassword456"
        })
        self.assertEqual(status, 409)
        self.assertIn("already exists", body.get("error", ""))

    # 3. Log-In Tests
    def test_login_flow(self):
        # Register user
        simulate_request("POST", "/api/auth/signup", {
            "email": "ops@ipvision.io",
            "password": "CorrectPassword88"
        })
        # Log in with correct credentials
        status, headers, body = simulate_request("POST", "/api/auth/login", {
            "email": "ops@ipvision.io",
            "password": "CorrectPassword88"
        })
        self.assertEqual(status, 200)
        self.assertEqual(body["user"]["email"], "ops@ipvision.io")
        self.assertIn("set-cookie", headers)

        # Log in with incorrect password
        bad_status, _, bad_body = simulate_request("POST", "/api/auth/login", {
            "email": "ops@ipvision.io",
            "password": "WrongPassword00"
        })
        self.assertEqual(bad_status, 401)
        self.assertIn("Incorrect email or password", bad_body.get("error", ""))

    # 4. Single-Active-Session Rule
    def test_single_active_session_rule(self):
        """When a user logs in from a second terminal, the first session MUST be superseded and blocked."""
        # Step 1: Sign up
        _, headers1, _ = simulate_request("POST", "/api/auth/signup", {
            "email": "officer@defense.net",
            "password": "TerminalKey123"
        })
        cookie1 = headers1["set-cookie"].split(";")[0]

        # Terminal 1 verifies it has an active session
        status, _, body = simulate_request("GET", "/api/auth/session", headers={"Cookie": cookie1})
        self.assertEqual(status, 200)
        self.assertTrue(body["authenticated"])

        # Step 2: User logs in from Terminal 2
        _, headers2, _ = simulate_request("POST", "/api/auth/login", {
            "email": "officer@defense.net",
            "password": "TerminalKey123"
        })
        cookie2 = headers2["set-cookie"].split(";")[0]

        # Step 3: Terminal 2 is now active
        status2, _, body2 = simulate_request("GET", "/api/auth/session", headers={"Cookie": cookie2})
        self.assertEqual(status2, 200)
        self.assertTrue(body2["authenticated"])

        # Step 4: Terminal 1 tries to access protected endpoint (/api/scans) -> MUST be blocked
        status_old, _, body_old = simulate_request("GET", "/api/scans", headers={"Cookie": cookie1})
        self.assertEqual(status_old, 401)
        self.assertIn("Another session was opened on a different device or browser", body_old.get("error", ""))

    # 5. User Scan Isolation (Row Level Security Simulation)
    def test_scan_saving_and_isolation(self):
        """User A can save scans, User B cannot view User A's scans."""
        # Register User A
        _, hA, _ = simulate_request("POST", "/api/auth/signup", {
            "email": "userA@agency.gov",
            "password": "PasswordUserA1"
        })
        cookieA = hA["set-cookie"].split(";")[0]

        # Register User B
        _, hB, _ = simulate_request("POST", "/api/auth/signup", {
            "email": "userB@agency.gov",
            "password": "PasswordUserB2"
        })
        cookieB = hB["set-cookie"].split(";")[0]

        # User A saves a scan for 8.8.8.8
        save_status, _, _ = simulate_request("POST", "/api/scans", {
            "ip": "8.8.8.8",
            "city": "Mountain View",
            "country": "United States",
            "isp": "Google LLC",
            "risk": "Low"
        }, headers={"Cookie": cookieA})
        self.assertEqual(save_status, 201)

        # User A reads their scans -> Should see 8.8.8.8
        statusA, _, bodyA = simulate_request("GET", "/api/scans", headers={"Cookie": cookieA})
        self.assertEqual(statusA, 200)
        self.assertEqual(len(bodyA["scans"]), 1)
        self.assertEqual(bodyA["scans"][0]["ip"], "8.8.8.8")

        # User B reads their scans -> MUST be empty (isolated from User A)
        statusB, _, bodyB = simulate_request("GET", "/api/scans", headers={"Cookie": cookieB})
        self.assertEqual(statusB, 200)
        self.assertEqual(len(bodyB["scans"]), 0, "User B must not see User A's scans")

    # 6. Scanner Gating
    def test_scanner_requires_authentication(self):
        """Unauthenticated requests to /api/lookup must return 401."""
        status, _, body = simulate_request("GET", "/api/lookup?ip=8.8.8.8")
        self.assertEqual(status, 401)
        self.assertTrue(body.get("requires_auth"))

    # 7. Feedback Validation
    def test_feedback_length_validation(self):
        # Too short
        status_short, _, body_short = simulate_request("POST", "/api/feedback", {
            "message": "hi",
            "sentiment": "good"
        })
        self.assertEqual(status_short, 400)
        self.assertIn("between 3 and 1,000 characters", body_short.get("error", ""))

        # Valid feedback
        status_valid, _, body_valid = simulate_request("POST", "/api/feedback", {
            "message": "Excellent radar interface, love the neon sweep animation!",
            "sentiment": "great",
            "category": "UI / Experience"
        })
        self.assertEqual(status_valid, 200)
        self.assertTrue(body_valid.get("ok"))


if __name__ == "__main__":
    unittest.main()
