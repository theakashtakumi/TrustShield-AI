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
        server.RATE_BUCKETS.clear()
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
        pdf = b"%PDF-1.4\nreceipt details\n%%EOF"
        payload = {"url": "https://shop.example", "business": "Example Shop", "category": "Non-delivery after payment", "details": "I paid last week and have not received my order.", "incident_date": "2026-11-01", "agree": True,
                   "evidence_files": [{"name": "receipt.png", "mime_type": "image/png", "data": base64.b64encode(png).decode()}, {"name": "order.pdf", "mime_type": "application/pdf", "data": base64.b64encode(pdf).decode()}]}
        submit = FakeRequestHandler("POST", "/api/reports", payload, cookie)
        with patch.object(server, "safe_public_host"):
            submit.do_POST()
        report_id = submit.body()["id"]
        with server.db() as conn:
            report = conn.execute("SELECT status,evidence_name,evidence_path FROM reports WHERE id=?", (report_id,)).fetchone()
        self.assertEqual(report["status"], "Submitted")
        self.assertEqual(report["evidence_name"], "receipt.png")
        self.assertEqual((server.UPLOAD_DIR / report["evidence_path"]).read_bytes(), png)
        owner_detail = FakeRequestHandler("GET", f"/api/reports/{report_id}", cookie=cookie)
        owner_detail.do_GET()
        self.assertIn("Evidence authenticity", [item["label"] for item in owner_detail.body()["evidence_analysis"]["checks"]])
        self.assertEqual(len(owner_detail.body()["evidence_files"]), 2)
        attachment_id = next(item["id"] for item in owner_detail.body()["evidence_files"] if item["kind"] == "additional")
        extra_evidence = FakeRequestHandler("GET", f"/api/reports/{report_id}/evidence/attachment/{attachment_id}", cookie=cookie)
        extra_evidence.do_GET()
        self.assertTrue(extra_evidence.wfile.getvalue().endswith(pdf))
        denied_evidence = FakeRequestHandler("GET", f"/api/reports/{report_id}/evidence")
        denied_evidence.do_GET()
        self.assertEqual(denied_evidence.body()["error"], "Evidence not found.")
        allowed_evidence = FakeRequestHandler("GET", f"/api/reports/{report_id}/evidence", cookie=cookie)
        allowed_evidence.do_GET()
        self.assertTrue(allowed_evidence.wfile.getvalue().endswith(png))
        public_history = FakeRequestHandler("GET", "/api/history")
        public_history.do_GET()
        self.assertEqual(public_history.body()["reports"], [])
        private_report = FakeRequestHandler("GET", f"/api/reports/{report_id}")
        private_report.do_GET()
        self.assertEqual(private_report.body()["error"], "Report not found.")
        reviewing = FakeRequestHandler("PATCH", f"/api/admin/reports/{report_id}/status", {"status": "Under Review", "note": "Beginning the evidence review."}, cookie)
        reviewing.do_PATCH()
        moderate = FakeRequestHandler("PATCH", f"/api/admin/reports/{report_id}/status", {"status": "Partially Supported", "note": "Receipt supports that payment was made."}, cookie)
        moderate.do_PATCH()
        with server.db() as conn:
            event = conn.execute("SELECT old_status,new_status,note FROM moderation_events WHERE report_id=? ORDER BY id DESC LIMIT 1", (report_id,)).fetchone()
        self.assertEqual(tuple(event), ("Under Review", "Partially Supported", "Receipt supports that payment was made."))

    def test_guidance_actions_notifications_and_followup_evidence(self):
        _user, cookie = self.register_admin()
        payload = {"url": "https://help.example", "category": "Phishing or suspicious links.", "details": "I received a suspicious login link by email.", "agree": True}
        submit = FakeRequestHandler("POST", "/api/reports", payload, cookie)
        with patch.object(server, "safe_public_host"):
            submit.do_POST()
        report_id = submit.body()["id"]
        detail = FakeRequestHandler("GET", f"/api/reports/{report_id}", cookie=cookie)
        detail.do_GET()
        guidance = detail.body()["guidance"]
        self.assertGreaterEqual(len(guidance["steps"]), 5)
        self.assertTrue(any("National Cyber Crime" in item["title"] for item in guidance["resources"]))
        action = FakeRequestHandler("POST", f"/api/reports/{report_id}/actions", {"action_id": guidance["steps"][0]["id"], "completed": True}, cookie)
        action.do_POST()
        detail = FakeRequestHandler("GET", f"/api/reports/{report_id}", cookie=cookie)
        detail.do_GET()
        self.assertIn(guidance["steps"][0]["id"], detail.body()["completed_guidance_actions"])
        request_info = FakeRequestHandler("PATCH", f"/api/admin/reports/{report_id}/status", {"status": "More Information Required", "note": "Need the original message context.", "public_message": "Please attach the sender details and a screenshot."}, cookie)
        request_info.do_PATCH()
        followup = FakeRequestHandler("POST", f"/api/reports/{report_id}/followups", {"details": "I have added the email sender and date."}, cookie)
        followup.do_POST()
        self.assertEqual(followup.body()["message"], "Your update was added to the report.")
        notification_list = FakeRequestHandler("GET", "/api/notifications", cookie=cookie)
        notification_list.do_GET()
        self.assertGreaterEqual(notification_list.body()["unread"], 2)
        notification_id = notification_list.body()["notifications"][0]["id"]
        read = FakeRequestHandler("POST", f"/api/notifications/{notification_id}/read", {}, cookie)
        read.do_POST()
        self.assertEqual(read.body(), {"ok": True})

    def test_report_access_search_duplicate_and_dispute_review(self):
        _user, cookie = self.register_admin()
        first = {"url": "https://same.example", "category": "Payment fraud or suspicious transaction.", "details": "I saw an unfamiliar charge after visiting the store.", "agree": True}
        submit = FakeRequestHandler("POST", "/api/reports", first)
        with patch.object(server, "safe_public_host"):
            submit.do_POST()
        first_id = submit.body()["id"]
        second = {**first, "url": "https://www.same.example/path", "details": "I noticed an unfamiliar charge after I visited this store."}
        submit2 = FakeRequestHandler("POST", "/api/reports", second)
        with patch.object(server, "safe_public_host"):
            submit2.do_POST()
        second_id = submit2.body()["id"]
        self.assertTrue(submit2.body()["evidence_analysis"]["possible_duplicates"])
        review = FakeRequestHandler("PATCH", f"/api/admin/reports/{first_id}/status", {"status": "Under Review", "note": "Initial review started."}, cookie)
        review.do_PATCH()
        unauthorized = FakeRequestHandler("PATCH", f"/api/admin/reports/{first_id}/status", {"status": "Verified Findings", "note": "Cannot bypass review."})
        unauthorized.do_PATCH()
        self.assertEqual(unauthorized.body()["error"], "Sign in to continue.")
        community = FakeRequestHandler("GET", "/api/community?q=same.example&status=Under%20Review&page=1")
        community.do_GET()
        self.assertEqual(community.body()["total"], 1)
        self.assertEqual(community.body()["reports"][0]["id"], first_id)
        public_detail = FakeRequestHandler("GET", f"/api/reports/{first_id}")
        public_detail.do_GET()
        self.assertNotIn("reference", public_detail.body())
        self.assertNotIn("links", public_detail.body())
        dispute = FakeRequestHandler("POST", f"/api/reports/{first_id}/disputes", {"reason": "This report refers to a different store; please review."})
        dispute.do_POST()
        admin_detail = FakeRequestHandler("GET", f"/api/reports/{first_id}", cookie=cookie)
        admin_detail.do_GET()
        dispute_id = admin_detail.body()["disputes"][0]["id"]
        decide = FakeRequestHandler("PATCH", f"/api/admin/reports/{first_id}/flags/{dispute_id}", {"status": "Needs follow-up", "reason": "We need more context to decide."}, cookie)
        decide.do_PATCH()
        self.assertEqual(decide.body()["status"], "Needs follow-up")

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
