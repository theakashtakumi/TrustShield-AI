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
    def __init__(self, method, path, payload=None, cookie=""):
        self.command = method
        self.path = path
        self.requestline = f"{method} {path} HTTP/1.1"
        self.request_version = "HTTP/1.1"
        self.client_address = ("127.0.0.1", 50000)
        self.headers = email.message.Message()
        encoded = json.dumps(payload or {}).encode()
        self.headers["Content-Length"] = str(len(encoded))
        if cookie:
            self.headers["Cookie"] = cookie
        self.rfile = io.BytesIO(encoded)
        self.wfile = io.BytesIO()
        self._headers_buffer = []
        self.server = type("LocalServer", (), {"server_version": "TrustShield/1.0", "sys_version": ""})()

    def body(self):
        return json.loads(self.wfile.getvalue().split(b"\r\n\r\n", 1)[1])

    def status(self):
        return int(self.wfile.getvalue().split(b" ", 2)[1])

    def response_headers(self):
        return self.wfile.getvalue().split(b"\r\n\r\n", 1)[0].decode("latin1")


class AdminOperationsTests(unittest.TestCase):
    def setUp(self):
        server.RATE_BUCKETS.clear()
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.old_db, self.old_upload = server.DB_PATH, server.UPLOAD_DIR
        self.old_admin = os.environ.get("TRUSTSHIELD_ADMIN_EMAIL")
        self.old_token = os.environ.get("TRUSTSHIELD_ADMIN_BOOTSTRAP_TOKEN")
        server.DB_PATH = Path(self.temp.name) / "admin.sqlite"
        server.UPLOAD_DIR = Path(self.temp.name) / "uploads"
        os.environ["TRUSTSHIELD_ADMIN_EMAIL"] = "admin@example.com"
        os.environ["TRUSTSHIELD_ADMIN_BOOTSTRAP_TOKEN"] = "test-bootstrap-token"
        server.init_db()
        self.admin, self.admin_cookie = self.register("Admin", "admin@example.com", "test-bootstrap-token")
        self.member, self.member_cookie = self.register("Member", "member@example.com")

    def tearDown(self):
        server.DB_PATH, server.UPLOAD_DIR = self.old_db, self.old_upload
        if self.old_admin is None:
            os.environ.pop("TRUSTSHIELD_ADMIN_EMAIL", None)
        else:
            os.environ["TRUSTSHIELD_ADMIN_EMAIL"] = self.old_admin
        if self.old_token is None:
            os.environ.pop("TRUSTSHIELD_ADMIN_BOOTSTRAP_TOKEN", None)
        else:
            os.environ["TRUSTSHIELD_ADMIN_BOOTSTRAP_TOKEN"] = self.old_token
        self.temp.cleanup()

    def register(self, name, email, admin_token=""):
        handler = FakeRequestHandler("POST", "/api/auth/register", {
            "name": name, "email": email, "password": "strong-test-password-123", "admin_token": admin_token,
        })
        handler.do_POST()
        cookie = next(line for line in handler.response_headers().split("\r\n") if line.lower().startswith("set-cookie:"))
        return handler.body(), cookie.split(":", 1)[1].strip().split(";", 1)[0]

    def request(self, method, path, payload=None, cookie=None):
        handler = FakeRequestHandler(method, path, payload, cookie or self.admin_cookie)
        getattr(handler, f"do_{method}")()
        return handler

    def seed_report(self, status="Submitted"):
        with server.db() as conn:
            cursor = conn.execute(
                "INSERT INTO reports(url,category,details,evidence,created_at,domain,status,user_id) VALUES(?,?,?,?,?,?,?,?)",
                ("https://shop.example", "Payment fraud", "The checkout requested an unusual transfer.", "", server.now(), "shop.example", status, self.member["id"]),
            )
            return cursor.lastrowid

    def test_admin_reads_are_protected_and_live_overview_is_backed_by_database(self):
        report_id = self.seed_report()
        guest = FakeRequestHandler("GET", "/api/admin/users")
        guest.do_GET()
        self.assertEqual(guest.status(), 401)

        overview = self.request("GET", "/api/admin/overview?days=7")
        self.assertEqual(overview.status(), 200)
        self.assertEqual(overview.body()["metrics"]["total_users"], 2)
        self.assertEqual(len(overview.body()["scans_by_day"]), 7)
        reports = self.request("GET", "/api/admin/reports?q=shop.example")
        self.assertEqual(reports.body()["total"], 1)
        self.assertEqual(reports.body()["reports"][0]["id"], report_id)
        users = self.request("GET", "/api/admin/users?q=member")
        self.assertEqual(users.body()["users"][0]["email"], "member@example.com")

    def test_scanner_settings_are_validated_persisted_and_audited(self):
        update = self.request("PATCH", "/api/admin/scanner/settings", {
            "request_timeout_seconds": 6,
            "max_redirects": 2,
            "phishing_heuristics_enabled": False,
        })
        self.assertEqual(update.status(), 200)
        self.assertEqual(server.scanner_configuration()["request_timeout_seconds"], 6)
        self.assertEqual(server.scanner_configuration()["max_redirects"], 2)
        self.assertFalse(server.scanner_configuration()["phishing_heuristics_enabled"])
        invalid = self.request("PATCH", "/api/admin/scanner/settings", {"request_timeout_seconds": 99})
        self.assertEqual(invalid.status(), 400)
        audit = self.request("GET", "/api/admin/audit?q=scanner.settings_changed")
        self.assertEqual(audit.body()["events"][0]["action"], "scanner.settings_changed")

    def test_suspension_revokes_sessions_and_roles_are_audited(self):
        suspended = self.request("PATCH", f"/api/admin/users/{self.member['id']}/status", {"status": "suspended"})
        self.assertEqual(suspended.status(), 200)
        member_session = FakeRequestHandler("GET", "/api/auth/me", cookie=self.member_cookie)
        member_session.do_GET()
        self.assertEqual(member_session.status(), 401)
        activated = self.request("PATCH", f"/api/admin/users/{self.member['id']}/status", {"status": "active"})
        self.assertEqual(activated.status(), 200)
        promoted = self.request("PATCH", f"/api/admin/users/{self.member['id']}/role", {"role": "admin"})
        self.assertEqual(promoted.status(), 200)
        audit = self.request("GET", "/api/admin/audit?q=user.role_changed")
        self.assertEqual(audit.body()["events"][0]["action"], "user.role_changed")

    def test_verified_report_gates_threat_record_and_incident_actions_are_timeline_logged(self):
        report_id = self.seed_report()
        rejected = self.request("POST", "/api/admin/threats", {"report_id": report_id, "verification_note": "Evidence was reviewed and the claim is verified."})
        self.assertEqual(rejected.status(), 409)
        self.request("PATCH", f"/api/admin/reports/{report_id}/status", {"status": "Under Review", "note": "Starting the documented review."})
        self.request("PATCH", f"/api/admin/reports/{report_id}/status", {"status": "Verified Findings", "note": "Submitted evidence supports the reported transaction."})
        assigned = self.request("PATCH", f"/api/admin/reports/{report_id}", {"assigned_to": self.admin["id"], "priority": "high"})
        self.assertEqual(assigned.status(), 200)
        note = self.request("POST", f"/api/admin/reports/{report_id}/notes", {"note": "The transaction reference was checked against the uploaded receipt."})
        self.assertEqual(note.status(), 201)
        public = FakeRequestHandler("GET", f"/api/reports/{report_id}")
        public.do_GET()
        self.assertNotIn("assigned_to", public.body())
        self.assertNotIn("priority", public.body())

        threat = self.request("POST", "/api/admin/threats", {"report_id": report_id, "verification_note": "Receipt and destination domain were reviewed by a moderator."})
        self.assertEqual(threat.status(), 201)
        self.assertEqual(threat.body()["domain"], "shop.example")

        class FakeResponse:
            status = 200
            headers = email.message.Message()
            headers["Content-Type"] = "text/html; charset=utf-8"
            def __enter__(self): return self
            def __exit__(self, *_args): return False
            def geturl(self): return "https://shop.example/"
            def read(self, _size): return b"<html><title>Shop</title><p>Product information</p></html>"

        opener = type("FakeOpener", (), {"open": lambda *_args, **_kwargs: FakeResponse()})()
        with patch.object(server, "safe_public_host", return_value=("203.0.113.5",)), patch.object(server.urllib.request, "build_opener", return_value=opener):
            scan = server.scan_site("shop.example")
        self.assertEqual(scan["verified_threat_match"]["id"], threat.body()["id"])
        self.assertEqual(scan["score"], 100 - scan["calculation"]["warning_points"])
        incident = self.request("POST", "/api/admin/incidents", {
            "title": "Review related shop complaints", "severity": "high", "assigned_to": self.admin["id"], "report_ids": [report_id], "note": "Open the case for linked report review.",
        })
        self.assertEqual(incident.status(), 201)
        incident_id = incident.body()["id"]
        self.request("POST", f"/api/admin/incidents/{incident_id}/events", {"note": "Checked the seller contact details against the report evidence."})
        update = self.request("PATCH", f"/api/admin/incidents/{incident_id}", {"status": "investigating", "severity": "critical", "note": "Investigation started."})
        self.assertEqual(update.status(), 200)
        detail = self.request("GET", f"/api/admin/incidents/{incident_id}")
        self.assertEqual(len(detail.body()["reports"]), 1)
        self.assertGreaterEqual(len(detail.body()["events"]), 3)
        audit = self.request("GET", "/api/admin/audit?q=incident")
        self.assertTrue(any("incident" in event["resource_type"] for event in audit.body()["events"]))


if __name__ == "__main__":
    unittest.main()
