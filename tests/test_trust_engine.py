import unittest

from trust_engine import classify


class TrustEngineTests(unittest.TestCase):
    def test_score_tiers_are_weighted_and_bounded(self):
        self.assertEqual((classify(0)["score"], classify(0)["label"]), (100, "Low Risk"))
        self.assertEqual((classify(16)["score"], classify(16)["label"]), (84, "Moderate Risk"))
        self.assertEqual((classify(35)["score"], classify(35)["label"]), (65, "High Risk"))
        self.assertEqual((classify(60)["score"], classify(60)["label"]), (40, "Critical Risk"))
        self.assertEqual(classify(500)["risk_points"], 100)
        self.assertEqual(classify(-2)["score"], 100)

    def test_unavailable_data_is_not_treated_as_a_high_score(self):
        result = classify(0, sufficient_data=False)
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["label"], "Insufficient Data")
        self.assertIn("not an endorsement", result["summary"])


if __name__ == "__main__":
    unittest.main()
