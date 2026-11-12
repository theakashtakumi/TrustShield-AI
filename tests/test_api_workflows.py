import base64
import email.message
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import server


class FakeRequestHandler(server.Handler):
    """Run BaseHTTPRequestHandler routes without binding a network socket."""
    def __init__(self, method, path, payload=None, cookie=""):
        self.command = method
        self.path = path
        self.requestline = f"{method} {path} HTTP/1.1"
        self.request_version = "HTTP/1.1"
        self.client_address = ("127.0.0.1", 50000)
        self.headers = email.message.Message()
        self.headers["Content-Length"] = str(len(json.dumps(payload or {}).encode()))
        if cookie:
            self.headers["Cookie"] = cookie
        self.rfile = io.BytesIO(json.dumps(payload or {}).encode())
        self.wfile = io.BytesIO()
        self._headers_buffer = []
        self.server = type("LocalServer", (), {"server_version": "TrustShield/1.0", "sys_version": ""})()

    def body(self):
        return json.loads(self.wfile.getvalue().split(b"\r\n\r\n", 1)[1])

    def response_headers(self):
        return self.wfile.getvalue().split(b"\r\n\r\n", 1)[0].decode("latin1")


class ApiWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.old_db, self.old_upload = server.DB_PATH, server.UPLOAD_DIR
        self.old_admin = os.environ.get("TRUSTSHIELD_ADMIN_EMAIL")
        self.old_admin_token = os.environ.get("TRUSTSHIELD_ADMIN_BOOTSTRAP_TOKEN")
        server.DB_PATH = Path(self.temp.name) / "test.sqlite"
        server.UPLOAD_DIR = Path(self.temp.name) / "uploads"
        os.environ["TRUSTSHIELD_ADMIN_EMAIL"] = "admin@example.com"
        os.environ["TRUSTSHIELD_ADMIN_BOOTSTRAP_TOKEN"] = "one-time-admin-token"
        server.init_db()

    def tearDown(self):
        server.DB_PATH, server.UPLOAD_DIR = self.old_db, self.old_upload
        if self.old_admin is None:
            os.environ.pop("TRUSTSHIELD_ADMIN_EMAIL", None)
        else:
            os.environ["TRUSTSHIELD_ADMIN_EMAIL"] = self.old_admin
        if self.old_admin_token is None:
            os.environ.pop("TRUSTSHIELD_ADMIN_BOOTSTRAP_TOKEN", None)
        else:
            os.environ["TRUSTSHIELD_ADMIN_BOOTSTRAP_TOKEN"] = self.old_admin_token
        self.temp.cleanup()

    def register_admin(self):
        handler = FakeRequestHandler("POST", "/api/auth/register", {"name": "Admin", "email": "admin@example.com", "password": "long-password-123", "admin_token": "one-time-admin-token"})
        handler.do_POST()
        cookie_line = next(line for line in handler.response_headers().split("\r\n") if line.lower().startswith("set-cookie:"))
        return handler.body(), cookie_line.split(":", 1)[1].strip().split(";", 1)[0]

    def test_account_password_hash_and_session_are_created(self):
        user, cookie = self.register_admin()
        self.assertEqual(user["role"], "admin")
        with server.db() as conn:
            saved_hash = conn.execute("SELECT password_hash FROM users WHERE email='admin@example.com'").fetchone()[0]
        self.assertTrue(server.verify_password("long-password-123", saved_hash))
        self.assertFalse(server.verify_password("wrong-password", saved_hash))
        me = FakeRequestHandler("GET", "/api/auth/me", cookie=cookie)
        me.do_GET()
        self.assertEqual(me.body()["email"], "admin@example.com")

    def test_admin_email_without_bootstrap_token_is_not_elevated(self):
        registration = FakeRequestHandler("POST", "/api/auth/register", {"name": "Not admin", "email": "admin@example.com", "password": "long-password-123"})
        registration.do_POST()
        self.assertEqual(registration.body()["role"], "user")

    def test_report_upload_and_admin_verification_history(self):
        _user, cookie = self.register_admin()
        png = b"\x89PNG\r\n\x1a\n" + b"small-file"
        payload = {"url": "https://shop.example", "business": "Example Shop", "category": "Non-delivery after payment", "details": "I paid last week and have not received my order.", "incident_date": "2026-11-01", "agree": True,
                   "evidence_file": {"name": "receipt.png", "mime_type": "image/png", "data": base64.b64encode(png).decode()}}
        submit = FakeRequestHandler("POST", "/api/reports", payload, cookie)
        with patch.object(server, "safe_public_host"):
            submit.do_POST()
        report_id = submit.body()["id"]
        with server.db() as conn:
            report = conn.execute("SELECT status,evidence_name,evidence_path FROM reports WHERE id=?", (report_id,)).fetchone()
        self.assertEqual(report["status"], "Submitted")
        self.assertEqual(report["evidence_name"], "receipt.png")
        self.assertEqual((server.UPLOAD_DIR / report["evidence_path"]).read_bytes(), png)
        public_history = FakeRequestHandler("GET", "/api/history")
        public_history.do_GET()
        self.assertEqual(public_history.body()["reports"], [])
        private_report = FakeRequestHandler("GET", f"/api/reports/{report_id}")
        private_report.do_GET()
        self.assertEqual(private_report.body()["error"], "Report not found.")
        moderate = FakeRequestHandler("PATCH", f"/api/admin/reports/{report_id}/status", {"status": "Partially Verified", "note": "Order evidence checked."}, cookie)
        moderate.do_PATCH()
        with server.db() as conn:
            event = conn.execute("SELECT old_status,new_status,note FROM moderation_events WHERE report_id=?", (report_id,)).fetchone()
        self.assertEqual(tuple(event), ("Submitted", "Partially Verified", "Order evidence checked."))

    def test_report_requires_consent_and_rejects_mismatched_file(self):
        payload = {"url": "https://shop.example", "category": "Other concern", "details": "This website asked for payment.", "agree": False}
        request = FakeRequestHandler("POST", "/api/reports", payload)
        with patch.object(server, "safe_public_host"):
            request.do_POST()
        self.assertIn("community report notice", request.body()["error"])
        payload["agree"] = True
        payload["evidence_file"] = {"name": "fake.png", "mime_type": "image/png", "data": base64.b64encode(b"%PDF-pretending-to-be-a-png").decode()}
        mismatch = FakeRequestHandler("POST", "/api/reports", payload)
        with patch.object(server, "safe_public_host"):
            mismatch.do_POST()
        self.assertIn("does not match", mismatch.body()["error"])

    def test_guest_report_can_be_revisited_with_its_private_token(self):
        payload = {"url": "https://guest.example", "category": "Other concern", "details": "The price shown changed before checkout.", "agree": True}
        submit = FakeRequestHandler("POST", "/api/reports", payload)
        with patch.object(server, "safe_public_host"):
            submit.do_POST()
        result = submit.body()
        self.assertTrue(result["guest_token"])
        history = FakeRequestHandler("GET", "/api/history")
        history.headers["X-TrustShield-Guest-Tokens"] = result["guest_token"]
        history.do_GET()
        self.assertEqual(history.body()["my_reports"][0]["id"], result["id"])


if __name__ == "__main__":
    unittest.main()
