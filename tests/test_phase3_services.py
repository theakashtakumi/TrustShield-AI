import unittest

from evidence_service import analyze_evidence, inspect_file, related_hosts
from guidance_service import guidance_for


class Phase3ServiceTests(unittest.TestCase):
    def test_guidance_is_category_specific_and_uses_verified_official_resources(self):
        phishing = guidance_for("Phishing or suspicious links.")
        delivery = guidance_for("Payment taken, but product or service not delivered.")
        self.assertNotEqual([item["text"] for item in phishing["steps"]], [item["text"] for item in delivery["steps"]])
        self.assertTrue(any("cybercrime.gov.in" in item["url"] for item in phishing["resources"]))
        self.assertTrue(any("consumerhelpline.gov.in" in item["url"] for item in delivery["resources"]))
        self.assertIn("not legal or financial advice", phishing["disclaimer"])
        self.assertIn("guarantee recovery", phishing["disclaimer"])

    def test_evidence_analysis_separates_file_checks_from_claim_support(self):
        evidence = inspect_file("payment-receipt.txt", "text/plain", b"Payment was received on 2026-11-01.")
        result = analyze_evidence({
            "url": "https://shop.example", "category": "Payment fraud or suspicious transaction.",
            "details": "An unfamiliar payment request appeared after checkout and the shop did not reply.",
            "incident_date": "2026-11-03", "created_at": "2026-11-12", "links": "https://www.shop.example/order"
        }, [evidence], [], set())
        checks = {item["id"]: item for item in result["checks"]}
        self.assertTrue(checks["file_readability"]["status"] == "PASS")
        self.assertEqual(checks["evidence_authenticity"]["status"], "NOT ASSESSED")
        self.assertEqual(checks["claim_support"]["status"], "NOT DETERMINED")
        self.assertEqual(checks["url_relationship"]["status"], "PASS")
        self.assertTrue("human review" in result["assessment"])

    def test_related_domain_matching_is_boundary_aware(self):
        self.assertTrue(related_hosts("https://www.shop.example", "https://support.shop.example/help"))
        self.assertFalse(related_hosts("https://shop.example", "https://shop.example.evil.test"))
        self.assertFalse(related_hosts("https://shop.example", "https://different.example"))


if __name__ == "__main__":
    unittest.main()
