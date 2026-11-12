import email.message
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import server


class FakeResponse:
    status = 200

    def __init__(self, content):
        self.content = content
        self.headers = email.message.Message()
        self.headers["Content-Type"] = "text/html; charset=utf-8"
        self.headers["Strict-Transport-Security"] = "max-age=31536000"
        self.headers["Content-Security-Policy"] = "default-src 'self'"
        self.headers["X-Content-Type-Options"] = "nosniff"

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def geturl(self):
        return "https://shop.example/"

    def read(self, _size):
        return self.content


class ScannerTests(unittest.TestCase):
    def test_local_targets_are_rejected(self):
        with self.assertRaises(ValueError):
            server.normalize_url("http://127.0.0.1/admin")
        with self.assertRaises(ValueError):
            server.normalize_url("localhost")

    def test_url_normalization_adds_https_and_discards_fragment(self):
        with patch.object(server, "safe_public_host"):
            self.assertEqual(server.normalize_url("shop.example/path#section"), "https://shop.example/path")

    def test_scan_reports_live_page_findings_and_stores_results(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            previous_db, previous_upload = server.DB_PATH, server.UPLOAD_DIR
            server.DB_PATH = Path(directory) / "test.sqlite"
            server.UPLOAD_DIR = Path(directory) / "uploads"
            try:
                server.init_db()
                opener = type("FakeOpener", (), {"open": lambda *_args, **_kwargs: FakeResponse(b"<html><title>Shop</title><a href='/returns'>Returns</a><a href='/contact'>Contact us</a></html>")})()
                with patch.object(server, "safe_public_host"), patch.object(server.urllib.request, "build_opener", return_value=opener):
                    result = server.scan_site("shop.example")
                self.assertEqual(result["label"], "Low Risk")
                self.assertTrue(any(item["name"] == "Return and refund information" and item["status"] == "positive" for item in result["checks"]))
                with server.db() as conn:
                    saved = conn.execute("SELECT checks FROM scans WHERE id=?", (result["id"],)).fetchone()
                self.assertIn("Return and refund information", saved["checks"])
            finally:
                server.DB_PATH, server.UPLOAD_DIR = previous_db, previous_upload


if __name__ == "__main__":
    unittest.main()
