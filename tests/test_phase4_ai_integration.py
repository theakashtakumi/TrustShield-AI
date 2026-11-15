"""Phase 4 AI Integration & Governance Tests for TrustShield AI."""

import email.message
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

import server
from ai_services.phishing import analyze_phishing


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
        parts = self.wfile.getvalue().split(b"\r\n\r\n", 1)
        if len(parts) > 1 and parts[1]:
            return json.loads(parts[1])
        return {}

    def status(self):
        parts = self.wfile.getvalue().split(b" ", 2)
        return int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 200

    def response_headers(self):
        return self.wfile.getvalue().split(b"\r\n\r\n", 1)[0].decode("latin1")


class Phase4AiIntegrationTests(unittest.TestCase):
    def setUp(self):
        server.RATE_BUCKETS.clear()
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.old_db, self.old_upload = server.DB_PATH, server.UPLOAD_DIR
        self.old_admin = os.environ.get("TRUSTSHIELD_ADMIN_EMAIL")
        self.old_token = os.environ.get("TRUSTSHIELD_ADMIN_BOOTSTRAP_TOKEN")
        server.DB_PATH = Path(self.temp.name) / "test_phase4.sqlite"
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

    def test_admin_scans_returns_ai_and_phishing_analysis(self):
        ai_data = {
            "summary": "AI content assessment completed",
            "findings": [{"name": "Investment scam language", "severity": "high", "confidence": "high", "description": "High return claims", "evidence": "100% guarantee", "reasoning": "Unrealistic yield", "recommended_action": "Exercise caution"}],
            "limitations": ["Retrieved text only"],
        }
        phishing_data = {
            "findings": [{"id": "phishing.brand_similarity", "name": "Possible HDFC Bank domain similarity", "severity": "moderate", "evidence": "hdfcbank-login.xyz", "explanation": "Domain resembles official brand", "recommended_action": "Verify URL"}],
            "threat_intelligence": {"status": "not_configured"},
        }
        with server.db() as conn:
            conn.execute(
                "INSERT INTO scans(url,domain,score,label,summary,checks,ai_analysis,phishing_analysis,created_at,scanner_version,user_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                ("https://hdfcbank-login.xyz", "hdfcbank-login.xyz", 35, "Moderate Risk", "Lookalike domain", "[]", json.dumps(ai_data), json.dumps(phishing_data), server.now(), "1.0", self.member["id"]),
            )
            # Scan with default/empty analysis
            conn.execute(
                "INSERT INTO scans(url,domain,score,label,summary,checks,ai_analysis,phishing_analysis,created_at,scanner_version,user_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                ("https://example.com", "example.com", 85, "Low Risk", "Normal domain", "[]", "{}", "{}", server.now(), "1.0", self.member["id"]),
            )

        res = self.request("GET", "/api/admin/scans")
        self.assertEqual(res.status(), 200)
        body = res.body()
        self.assertIn("scans", body)
        self.assertEqual(len(body["scans"]), 2)

        s1 = body["scans"][0]
        s2 = body["scans"][1]

        # Scan 1 should have empty analysis safely converted to None
        self.assertEqual(s1["domain"], "example.com")
        self.assertIsNone(s1["ai_analysis"])
        self.assertIsNone(s1["phishing_analysis"])

        # Scan 2 should have parsed ai_analysis and phishing_analysis
        self.assertEqual(s2["domain"], "hdfcbank-login.xyz")
        self.assertIsInstance(s2["ai_analysis"], dict)
        self.assertEqual(s2["ai_analysis"]["summary"], "AI content assessment completed")
        self.assertIsInstance(s2["phishing_analysis"], dict)
        self.assertEqual(len(s2["phishing_analysis"]["findings"]), 1)
        self.assertEqual(s2["phishing_analysis"]["findings"][0]["severity"], "moderate")

    def test_admin_reports_list_has_ai_indicator(self):
        with server.db() as conn:
            # Report 1 with AI analysis
            conn.execute(
                "INSERT INTO reports(url,domain,business,category,status,priority,details,evidence,ai_analysis,created_at,user_id,evidence_name) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                ("https://fake-deal.in", "fake-deal.in", "Fake Deal", "Online shopping fraud", "Submitted", "high", "Lost payment", "", json.dumps({"version": "1.0.0"}), server.now(), self.member["id"], ""),
            )
            # Report 2 without AI analysis (default '{}')
            conn.execute(
                "INSERT INTO reports(url,domain,business,category,status,priority,details,evidence,ai_analysis,created_at,user_id,evidence_name) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                ("https://other.in", "other.in", "Other Shop", "Non-delivery", "Submitted", "normal", "Did not arrive", "", "{}", server.now(), self.member["id"], ""),
            )

        res = self.request("GET", "/api/admin/reports")
        self.assertEqual(res.status(), 200)
        reports = res.body()["reports"]
        self.assertEqual(len(reports), 2)
        r_ai = next(r for r in reports if r["domain"] == "fake-deal.in")
        r_no_ai = next(r for r in reports if r["domain"] == "other.in")
        self.assertEqual(r_ai["has_ai"], 1)
        self.assertEqual(r_no_ai["has_ai"], 0)

    def test_admin_report_detail_exposes_ai_analysis_and_feedback(self):
        sample_ai = {
            "version": "1.0.0",
            "complaint": {
                "local": {"triage": {"label": "suspicious_indicators"}},
                "ai": {
                    "status": "available",
                    "analysis_id": 42,
                    "triage": {"label": "suspicious_indicators", "confidence": 0.9, "category_alignment": "consistent"},
                    "risk_indicators": [{"name": "Urgent transfer", "description": "Demanded crypto transfer", "severity": "high", "confidence": "high", "evidence": "pay now", "recommended_action": "Do not pay"}],
                    "suggested_questions": ["What payment gateway was displayed?"],
                },
            },
            "evidence": {
                "extracted_information": {"amounts": ["INR 15,000"], "dates": ["2026-11-01"]},
                "potential_inconsistencies": ["Invoice date precedes order date"],
            },
            "related_patterns": [{"report_id": 99, "similarity": 0.88, "matching_info": "Similar fake domain pattern"}],
        }

        with server.db() as conn:
            cursor = conn.execute(
                "INSERT INTO reports(url,domain,business,category,status,priority,details,evidence,ai_analysis,ai_consent,created_at,user_id,evidence_name) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                ("https://scam-store.com", "scam-store.com", "Scam Store", "Payment fraud", "Under Review", "urgent", "Fake bank transfer", "", json.dumps(sample_ai), 1, server.now(), self.member["id"], ""),
            )
            report_id = cursor.lastrowid

        res = self.request("GET", f"/api/admin/reports/{report_id}")
        self.assertEqual(res.status(), 200)
        body = res.body()
        self.assertIsInstance(body["ai_analysis"], dict)
        self.assertEqual(body["ai_analysis"]["version"], "1.0.0")
        self.assertIn("ai_feedback", body)
        self.assertEqual(body["ai_feedback"], [])

    def test_ai_feedback_acceptance_and_rejection_persistence(self):
        ai_result = {
            "analysis_type": "complaint_intelligence",
            "risk_indicators": [
                {"name": "Impersonation", "severity": "high", "confidence": "high", "description": "Claims to be SBI officer", "evidence": "SBI logo", "recommended_action": "Verify credentials"}
            ],
        }
        with server.db() as conn:
            # Seed report
            cursor = conn.execute(
                "INSERT INTO reports(url,domain,business,category,status,priority,details,evidence,ai_analysis,ai_consent,created_at,user_id,evidence_name) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                ("https://sbi-verify.com", "sbi-verify.com", "SBI Clone", "Impersonation", "Under Review", "urgent", "Phishing call", "", json.dumps({"complaint": {"ai": ai_result}}), 1, server.now(), self.member["id"], ""),
            )
            report_id = cursor.lastrowid
            # Seed ai_run
            run_cur = conn.execute(
                "INSERT INTO ai_runs(resource_type,resource_id,domain,analysis_type,provider,model,model_version,prompt_version,input_sha256,status,result_json,usage_json,user_consented,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                ("report", report_id, "sbi-verify.com", "complaint_intelligence", "test_provider", "model-1", "1.0", "v1", "hash123", "available", json.dumps(ai_result), "{}", 1, server.now()),
            )
            run_id = run_cur.lastrowid

        # Accept feedback
        accept_res = self.request("POST", "/api/admin/ai/feedback", {
            "run_id": run_id,
            "finding_key": "risk_indicators:0",
            "decision": "accepted",
            "note": "Verified by moderator investigation.",
        })
        self.assertEqual(accept_res.status(), 200)
        self.assertTrue(accept_res.body().get("ok"))

        # Verify persisted in admin report detail
        detail_res = self.request("GET", f"/api/admin/reports/{report_id}")
        self.assertEqual(detail_res.status(), 200)
        feedback = detail_res.body()["ai_feedback"]
        self.assertEqual(len(feedback), 1)
        self.assertEqual(feedback[0]["decision"], "accepted")
        self.assertEqual(feedback[0]["finding_key"], "risk_indicators:0")

        # Reject feedback
        reject_res = self.request("POST", "/api/admin/ai/feedback", {
            "run_id": run_id,
            "finding_key": "risk_indicators:0",
            "decision": "rejected",
            "note": "Not an actual impersonation.",
        })
        self.assertEqual(reject_res.status(), 200)
        self.assertTrue(reject_res.body().get("ok"))

        # Non-admin cannot submit feedback
        member_res = self.request("POST", "/api/admin/ai/feedback", {
            "run_id": run_id,
            "finding_key": "risk_indicators:0",
            "decision": "accepted",
        }, cookie=self.member_cookie)
        self.assertEqual(member_res.status(), 403)

    def test_consent_enforcement_on_report_ai_analysis(self):
        with server.db() as conn:
            cursor = conn.execute(
                "INSERT INTO reports(url,domain,business,category,status,priority,details,evidence,ai_consent,created_at,user_id,evidence_name) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                ("https://private-store.com", "private-store.com", "Private Store", "Shopping", "Submitted", "normal", "Private details", "", 0, server.now(), self.member["id"], ""),
            )
            report_id = cursor.lastrowid

        # Admin cannot force AI analysis if reporter did not consent
        admin_req = self.request("POST", f"/api/reports/{report_id}/ai-analysis", {})
        self.assertEqual(admin_req.status(), 403)
        self.assertIn("reporter has not consented", admin_req.body()["error"].lower())

    def test_indian_brand_phishing_detection(self):
        # Suspicious lookalike domain for State Bank of India
        lookalike = analyze_phishing("https://sbi-secure-portal.com")
        findings = lookalike.get("findings", [])
        brand_findings = [f for f in findings if f.get("id") == "phishing.brand_similarity"]
        self.assertTrue(len(brand_findings) >= 1)
        # Rule check: Brand similarity alone must NEVER produce severity higher than moderate
        for bf in brand_findings:
            self.assertEqual(bf["severity"], "moderate")

        # Suspicious lookalike domain for Paytm
        paytm_lookalike = analyze_phishing("https://paytm-wallet-kyc.com")
        paytm_findings = [f for f in paytm_lookalike.get("findings", []) if f.get("id") == "phishing.brand_similarity"]
        self.assertTrue(len(paytm_findings) >= 1)
        self.assertEqual(paytm_findings[0]["severity"], "moderate")

        # Official domain must NOT trigger brand similarity false positive
        official_sbi = analyze_phishing("https://sbi.co.in")
        official_findings = [f for f in official_sbi.get("findings", []) if f.get("id") == "phishing.brand_similarity"]
        self.assertEqual(len(official_findings), 0)

        official_paytm = analyze_phishing("https://paytm.com")
        official_paytm_findings = [f for f in official_paytm.get("findings", []) if f.get("id") == "phishing.brand_similarity"]
        self.assertEqual(len(official_paytm_findings), 0)


if __name__ == "__main__":
    unittest.main()
