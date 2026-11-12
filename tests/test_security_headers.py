import unittest

from security_headers import (
    FAIL, NOT_APPLICABLE, NOT_DETECTED, PASS, WARNING,
    validate_csp, validate_hsts, validate_permissions_policy,
    validate_referrer_policy, validate_security_headers,
    validate_x_content_type_options, validate_x_frame_options,
)


class SecurityHeaderTests(unittest.TestCase):
    def test_hsts_checks_max_age_and_optional_scope(self):
        valid = validate_hsts("max-age=31536000; includeSubDomains")
        self.assertEqual(valid["status"], PASS)
        self.assertIn("including subdomains", valid["explanation"])
        self.assertEqual(validate_hsts("max-age=31536000")["status"], PASS)
        self.assertEqual(validate_hsts("max-age=0")["status"], WARNING)
        self.assertEqual(validate_hsts("includeSubDomains")["status"], FAIL)
        self.assertEqual(validate_hsts(None, is_https=False)["status"], NOT_APPLICABLE)
        self.assertEqual(validate_hsts(None)["status"], NOT_DETECTED)

    def test_csp_distinguishes_valid_strong_weak_and_invalid(self):
        strong = "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'"
        self.assertEqual(validate_csp(strong)["status"], PASS)
        self.assertEqual(validate_csp("default-src 'self'; script-src 'unsafe-inline'")["status"], WARNING)
        self.assertEqual(validate_csp("script-src 'self'; script-src *")["status"], FAIL)
        self.assertEqual(validate_csp("script-src 'self")["status"], FAIL)
        self.assertEqual(validate_csp(None)["status"], NOT_DETECTED)

    def test_simple_headers_validate_values_not_just_presence(self):
        self.assertEqual(validate_x_content_type_options(" NoSnIfF ")["status"], PASS)
        self.assertEqual(validate_x_content_type_options("sniff")["status"], FAIL)
        self.assertEqual(validate_x_frame_options("DENY")["status"], PASS)
        self.assertIn("any site", validate_x_frame_options("DENY")["explanation"])
        self.assertEqual(validate_x_frame_options("SAMEORIGIN")["status"], PASS)
        self.assertIn("same origin", validate_x_frame_options("SAMEORIGIN")["explanation"])

    def test_referrer_policy_checks_all_tokens_and_effective_policy(self):
        self.assertEqual(validate_referrer_policy("unsafe-url, strict-origin-when-cross-origin")["status"], PASS)
        self.assertEqual(validate_referrer_policy("unsafe-url")["status"], WARNING)
        self.assertEqual(validate_referrer_policy("made-up-policy")["status"], FAIL)

    def test_permissions_policy_accepts_restrictive_structured_dictionary(self):
        restrictive = 'camera=(), microphone=(), geolocation=(self "https://maps.example")'
        self.assertEqual(validate_permissions_policy(restrictive)["status"], PASS)
        self.assertEqual(validate_permissions_policy("camera=*")["status"], WARNING)
        self.assertEqual(validate_permissions_policy("camera=(self")["status"], FAIL)
        self.assertEqual(validate_permissions_policy(None)["status"], NOT_DETECTED)

    def test_all_six_headers_are_checked_with_observed_values(self):
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "SAMEORIGIN",
            "Referrer-Policy": "strict-origin",
            "Permissions-Policy": "camera=(), microphone=()",
        }
        findings = validate_security_headers(headers, is_https=True)
        self.assertEqual(len(findings), 6)
        self.assertTrue(all(item["status"] == PASS for item in findings))
        self.assertEqual(findings[0]["evidence"], "max-age=31536000")


if __name__ == "__main__":
    unittest.main()
