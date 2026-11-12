import base64
import email.message
import io
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
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

    def test_report_upload_rejects_evidence_over_the_documented_file_limit(self):
        oversized = b"\x89PNG\r\n\x1a\n" + b"x" * (2 * 1024 * 1024)
        payload = {"url": "https://shop.example", "category": "Other concern",
                   "details": "A sufficiently detailed report about this website.", "agree": True,
                   "evidence_file": {"name": "large.png", "mime_type": "image/png", "data": base64.b64encode(oversized).decode("ascii")}}
        request = FakeRequestHandler("POST", "/api/reports", payload)
        with patch.object(server, "safe_public_host"):
            request.do_POST()
        self.assertIn("2 MB", request.body()["error"])

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

    def test_guest_reports_do_not_leak_into_signed_in_accounts(self):
        guest_submit = FakeRequestHandler("POST", "/api/reports", {
            "url": "https://private-guest.example", "category": "Other concern",
            "details": "A guest report should stay with the guest token on this browser.", "agree": True,
        })
        with patch.object(server, "safe_public_host"):
            guest_submit.do_POST()
        guest_report = guest_submit.body()

        registration = FakeRequestHandler("POST", "/api/auth/register", {
            "name": "Member", "email": "member@example.com", "password": "long-password-123",
        })
        registration.do_POST()
        cookie = next(line for line in registration.response_headers().split("\r\n") if line.lower().startswith("set-cookie:"))
        session_cookie = cookie.split(":", 1)[1].strip().split(";", 1)[0]

        history = FakeRequestHandler("GET", "/api/history", cookie=session_cookie)
        history.headers["X-TrustShield-Guest-Tokens"] = guest_report["guest_token"]
        history.do_GET()
        self.assertEqual(history.body()["my_reports"], [])
        self.assertEqual(history.body()["overview"]["reports"], 0)

        notifications = FakeRequestHandler("GET", "/api/notifications", cookie=session_cookie)
        notifications.headers["X-TrustShield-Guest-Tokens"] = guest_report["guest_token"]
        notifications.do_GET()
        self.assertEqual(notifications.body()["notifications"], [])

        private_detail = FakeRequestHandler("GET", f"/api/reports/{guest_report['id']}", cookie=session_cookie)
        private_detail.headers["X-TrustShield-Guest-Tokens"] = guest_report["guest_token"]
        private_detail.do_GET()
        self.assertEqual(private_detail.body()["error"], "Report not found.")

        guest_history = FakeRequestHandler("GET", "/api/history")
        guest_history.headers["X-TrustShield-Guest-Tokens"] = guest_report["guest_token"]
        guest_history.do_GET()
        self.assertEqual(guest_history.body()["my_reports"][0]["id"], guest_report["id"])

    def test_report_date_rejects_future_but_accepts_reporters_local_today(self):
        future_date = (datetime.now(timezone.utc).date() + timedelta(days=1)).isoformat()
        future = FakeRequestHandler("POST", "/api/reports", {
            "url": "https://future-date.example", "category": "Other concern",
            "details": "This report uses an incident date that is after its submission date.",
            "incident_date": future_date, "timezone_offset_minutes": 0, "agree": True,
        })
        with patch.object(server, "safe_public_host"):
            future.do_POST()
        self.assertIn("not in the future", future.body()["error"])

        local_offset = -840
        local_today = (datetime.now(timezone.utc) - timedelta(minutes=local_offset)).date().isoformat()
        valid = FakeRequestHandler("POST", "/api/reports", {
            "url": "https://local-date.example", "category": "Other concern",
            "details": "This report uses the current date in the reporter’s local timezone.",
            "incident_date": local_today, "timezone_offset_minutes": local_offset, "agree": True,
        })
        with patch.object(server, "safe_public_host"), patch.object(server, "analyze_report_intelligence", return_value={}):
            valid.do_POST()
        result = valid.body()
        self.assertTrue(result.get("id"))
        with server.db() as conn:
            saved = conn.execute("SELECT evidence_analysis FROM reports WHERE id=?", (result["id"],)).fetchone()
        checks = {item["id"]: item for item in json.loads(saved["evidence_analysis"])["checks"]}
        self.assertEqual(checks["date_consistency"]["status"], "PASS")

    def test_ai_consent_provenance_human_feedback_and_curated_evaluation(self):
        _user, cookie = self.register_admin()
        report_payload = {"url": "https://seller.example", "category": "Non-delivery after payment",
                          "details": "I paid for an order, but the item did not arrive. The seller stopped replying.",
                          "agree": True, "ai_consent": False}
        with patch.object(server, "safe_public_host"), patch.object(server, "analyze_report_intelligence") as analysis:
            analysis.return_value = {"version": "1.0.0", "label": "AI-assisted analysis", "complaint": {"local": {"summary": "Local summary"}, "ai": {"status": "not_consented", "provider": "none"}}, "evidence": {}, "related_patterns": [], "moderator_brief": {"may_change_report_status": False}}
            submitted = FakeRequestHandler("POST", "/api/reports", report_payload, cookie)
            submitted.do_POST()
        report_id = submitted.body()["id"]
        self.assertFalse(analysis.call_args.kwargs["consent"])
        denied_retry = FakeRequestHandler("POST", f"/api/reports/{report_id}/ai-analysis", {"consent": False}, cookie)
        denied_retry.do_POST()
        self.assertIn("Explicit consent", denied_retry.body()["error"])
        with server.db() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM ai_runs").fetchone()[0], 0)

        finding = {"name": "Communication stopped", "description": "The report says the seller stopped replying.",
                   "severity": "moderate", "confidence": "low", "evidence": "seller stopped replying",
                   "recommended_action": "Ask whether another contact attempt was made."}
        def consented_analysis(_report, _files, _candidates, *, consent=False):
            self.assertTrue(consent)
            return {"version": "1.0.0", "label": "AI-assisted analysis", "external_processing_consent": True,
                    "complaint": {"local": {"summary": "The account awaits review."}, "ai": {
                        "analysis_type": "complaint_intelligence", "prompt_version": "test-1", "input_sha256": "a" * 64,
                        "provider": "fake", "model": "test-model", "model_version": "1",
                        "status": "available", "triage": "suspicious_indicators", "summary": "A neutral account summary.",
                        "risk_indicators": [finding], "usage": {"total_tokens": 9}}},
                    "evidence": {}, "related_patterns": [], "moderator_brief": {"may_change_report_status": False}}
        retry = FakeRequestHandler("POST", f"/api/reports/{report_id}/ai-analysis", {"consent": True}, cookie)
        with patch.object(server, "analyze_report_intelligence", side_effect=consented_analysis):
            retry.do_POST()
        self.assertTrue(retry.body()["report_status_unchanged"])
        with server.db() as conn:
            report = conn.execute("SELECT status,ai_consent FROM reports WHERE id=?", (report_id,)).fetchone()
            run = conn.execute("SELECT * FROM ai_runs WHERE resource_id=?", (report_id,)).fetchone()
        self.assertEqual(report["status"], "Submitted")
        self.assertEqual(report["ai_consent"], 1)
        self.assertEqual(run["provider"], "fake")
        self.assertEqual(run["model_version"], "1")
        self.assertEqual(run["user_consented"], 1)
        self.assertEqual(json.loads(run["usage_json"])["total_tokens"], 9)
        self.assertEqual(run["input_sha256"], "a" * 64)
        self.assertNotIn(report_payload["details"], run["result_json"])

        detail = FakeRequestHandler("GET", f"/api/reports/{report_id}", cookie=cookie)
        detail.do_GET()
        ai_run_id = detail.body()["ai_analysis"]["complaint"]["ai"]["analysis_id"]
        feedback = FakeRequestHandler("POST", "/api/admin/ai/feedback", {
            "run_id": ai_run_id, "finding_key": "risk_indicators:0", "decision": "accepted", "note": "Relevant account signal."}, cookie)
        feedback.do_POST()
        self.assertTrue(feedback.body()["ok"])
        reviewed_detail = FakeRequestHandler("GET", f"/api/reports/{report_id}", cookie=cookie)
        reviewed_detail.do_GET()
        self.assertEqual(reviewed_detail.body()["ai_feedback"][0]["decision"], "accepted")
        denied_feedback = FakeRequestHandler("POST", "/api/admin/ai/feedback", {
            "run_id": ai_run_id, "finding_key": "risk_indicators:4", "decision": "accepted"}, cookie)
        denied_feedback.do_POST()
        self.assertEqual(denied_feedback.response_headers().split("\r\n")[0].split()[1], "400")

        outcome = FakeRequestHandler("POST", f"/api/admin/reports/{report_id}/ai-outcome", {
            "label": "confirmed malicious activity", "partition": "evaluation", "note": "Reviewed order and correspondence."}, cookie)
        outcome.do_POST()
        self.assertTrue(outcome.body()["ok"])
        evaluation = FakeRequestHandler("GET", "/api/admin/ai/evaluation", cookie=cookie)
        evaluation.do_GET()
        self.assertEqual(evaluation.body()["overall"]["precision"], 1.0)
        split = FakeRequestHandler("POST", f"/api/admin/reports/{report_id}/ai-outcome", {
            "label": "confirmed malicious activity", "partition": "training", "note": "Do not split this same report."}, cookie)
        split.do_POST()
        self.assertEqual(split.response_headers().split("\r\n")[0].split()[1], "409")

        transition = FakeRequestHandler("PATCH", f"/api/admin/reports/{report_id}/status", {
            "status": "Under Review", "note": "Human review started."}, cookie)
        transition.do_PATCH()
        public = FakeRequestHandler("GET", f"/api/reports/{report_id}")
        public.do_GET()
        self.assertNotIn("ai_analysis", public.body())
        self.assertNotIn("ai_consent", public.body())
        self.assertNotIn("ai_feedback", public.body())


if __name__ == "__main__":
    unittest.main()
