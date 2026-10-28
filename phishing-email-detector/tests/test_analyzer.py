"""
Unit Tests for URL Analyzer, Header Analyzer, and Preprocessor.
"""

import sys
import os
import unittest

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from email_preprocessor import (
    clean_email_text,
    extract_linguistic_indicators,
    prepare_full_text
)
from url_analyzer import (
    extract_urls,
    is_ip_address,
    analyze_single_url,
    analyze_all_urls
)
from header_analyzer import (
    parse_email_address,
    extract_auth_status,
    analyze_email_headers
)


class TestPreprocessor(unittest.TestCase):

    def test_clean_email_text_entities_and_urls(self):
        raw = "Hello &amp; welcome! Visit https://malicious-site.top/login for $500 bonus!"
        cleaned = clean_email_text(raw)
        self.assertIn("__url_token__", cleaned)
        self.assertIn("__currency_token__", cleaned)
        self.assertNotIn("https://", cleaned)
        self.assertNotIn("&amp;", cleaned)

    def test_extract_linguistic_indicators(self):
        subject = "URGENT: ACCOUNT SUSPENDED IMMEDIATELY!"
        body = "Action required: click here to reset password or your account will be closed!"
        res = extract_linguistic_indicators(subject, body)
        self.assertGreater(res["urgency_keyword_count"], 0)
        self.assertGreater(res["linguistic_risk_score"], 30)
        self.assertGreater(res["exclamation_count"], 0)


class TestUrlAnalyzer(unittest.TestCase):

    def test_extract_urls(self):
        text = "Check http://example.com/test and https://login.bank.xyz/portal for info."
        urls = extract_urls(text)
        self.assertEqual(len(urls), 2)
        self.assertIn("http://example.com/test", urls)

    def test_ip_address_detection(self):
        self.assertTrue(is_ip_address("192.168.1.100"))
        self.assertTrue(is_ip_address("45.33.32.156:8080"))
        self.assertFalse(is_ip_address("google.com"))
        self.assertFalse(is_ip_address("paypal-security.top"))

    def test_suspicious_url_ip_host(self):
        url = "http://192.168.1.1/paypal/login"
        res = analyze_single_url(url)
        self.assertTrue(res["is_suspicious"])
        self.assertGreaterEqual(res["risk_score"], 40)
        self.assertTrue(any("raw IP" in flag for flag in res["flags"]))

    def test_suspicious_url_typosquatting(self):
        url = "http://login.paypal.account-verify.xyz/signin"
        res = analyze_single_url(url)
        self.assertTrue(res["is_suspicious"])
        self.assertTrue(any("brand impersonation" in flag.lower() for flag in res["flags"]))

    def test_legitimate_url(self):
        url = "https://github.com/torvalds/linux"
        res = analyze_single_url(url)
        self.assertFalse(res["is_suspicious"])
        self.assertLess(res["risk_score"], 30)


class TestHeaderAnalyzer(unittest.TestCase):

    def test_parse_email_address(self):
        name, addr, domain = parse_email_address("PayPal Support <support@paypal.com>")
        self.assertEqual(name, "PayPal Support")
        self.assertEqual(addr, "support@paypal.com")
        self.assertEqual(domain, "paypal.com")

    def test_reply_to_mismatch(self):
        res = analyze_email_headers(
            sender="service@paypal.com",
            reply_to="attacker@malicious-domain.xyz",
            subject="Test"
        )
        self.assertTrue(res["reply_to_mismatch"])
        self.assertGreaterEqual(res["header_risk_score"], 35)

    def test_display_name_spoofing(self):
        res = analyze_email_headers(
            sender="PayPal Security <hacker123@suspicious-free-mail.com>",
            subject="Urgent Alert"
        )
        self.assertTrue(res["display_name_spoofed"])
        self.assertGreaterEqual(res["header_risk_score"], 25)

    def test_spf_dkim_auth_parsing(self):
        headers = (
            "Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=example.com; dkim=pass; dmarc=pass\n"
            "Received-SPF: Pass\n"
        )
        res = analyze_email_headers(sender="alice@example.com", raw_headers=headers)
        self.assertEqual(res["spf_status"], "Pass")
        self.assertEqual(res["dkim_status"], "Pass")
        self.assertEqual(res["dmarc_status"], "Pass")

    def test_unknown_auth_status_when_headers_missing(self):
        res = analyze_email_headers(sender="bob@example.com", raw_headers="")
        self.assertEqual(res["spf_status"], "Unknown")
        self.assertEqual(res["dkim_status"], "Unknown")
        self.assertEqual(res["dmarc_status"], "Unknown")


if __name__ == "__main__":
    unittest.main()
