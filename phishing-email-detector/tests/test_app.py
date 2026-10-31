"""
End-to-End and Integration Tests for Flask API Endpoints.
"""

import sys
import os
import unittest
import json

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app
from database import init_db, clear_history


class TestFlaskEndpoints(unittest.TestCase):

    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()
        init_db()

    def test_index_route(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"PhishShield", res.data)
        self.assertIn(b"Email Ingestion Panel", res.data)

    def test_get_samples_route(self):
        res = self.client.get("/api/samples")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIn("phishing_credential", data["samples"])
        self.assertIn("legitimate_meeting", data["samples"])

    def test_get_metrics_route(self):
        res = self.client.get("/api/metrics")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIn("metrics", data)

    def test_scan_phishing_email(self):
        payload = {
            "sender": "Security Team <service@paypal-account-lock.top>",
            "reply_to": "attacker@darkweb-drop.xyz",
            "subject": "URGENT: Your account has been suspended! Verify immediately",
            "body": "Your bank account has unauthorized logins. Click http://192.168.1.50/verify to restore access immediately or funds will be lost.",
            "headers": "Authentication-Results: spf=fail; dkim=fail; dmarc=fail\nReceived-SPF: Fail"
        }
        res = self.client.post(
            "/api/scan",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIn(data["classification"], ["Phishing", "Suspicious"])
        self.assertGreater(data["composite_score"], 40)
        self.assertGreater(data["url_analysis"]["total_urls"], 0)
        self.assertTrue(data["header_analysis"]["reply_to_mismatch"])

    def test_scan_legitimate_email(self):
        payload = {
            "sender": "Professor Davis <davis@university.edu>",
            "reply_to": "davis@university.edu",
            "subject": "Cybersecurity Lecture Notes and Lab 4 Schedule",
            "body": "Hello class, the lecture slides on asymmetric encryption and RSA are now uploaded to the student portal. Have a great weekend.",
            "headers": "Authentication-Results: spf=pass; dkim=pass; dmarc=pass"
        }
        res = self.client.post(
            "/api/scan",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["classification"], "Likely Legitimate")
        self.assertLess(data["composite_score"], 40)

    def test_scan_empty_payload_validation(self):
        payload = {"body": "", "subject": ""}
        res = self.client.post(
            "/api/scan",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertFalse(data["success"])
        self.assertIn("error", data)

    def test_history_and_clear(self):
        # Scan one item
        self.client.post(
            "/api/scan",
            data=json.dumps({"subject": "Audit Check", "body": "Audit log verification test"}),
            content_type="application/json"
        )
        # Check history
        res = self.client.get("/api/history")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertGreaterEqual(len(data["scans"]), 1)

        # Clear history
        clear_res = self.client.post("/api/clear-history")
        self.assertEqual(clear_res.status_code, 200)
        clear_data = clear_res.get_json()
        self.assertTrue(clear_data["success"])

        # Check history is now empty
        res_after = self.client.get("/api/history")
        self.assertEqual(len(res_after.get_json()["scans"]), 0)

    def test_scan_graceful_handling_on_readonly_database_error(self):
        """Simulates Vercel read-only filesystem where SQLite write fails."""
        from unittest.mock import patch
        import sqlite3

        # Simulate sqlite3.OperationalError: attempt to write a readonly database
        with patch("app.save_scan_result", side_effect=sqlite3.OperationalError("attempt to write a readonly database")):
            payload = {
                "subject": "Urgent Security Alert",
                "body": "Your bank account has been locked. Verify immediately at http://192.168.1.1/login"
            }
            res = self.client.post(
                "/api/scan",
                data=json.dumps(payload),
                content_type="application/json"
            )
            # Must return 200 OK, NEVER 500!
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertTrue(data["success"])
            self.assertIsNone(data["scan_id"])
            self.assertFalse(data["history_saved"])
            self.assertIn("classification", data)
            self.assertGreater(data["composite_score"], 40)


if __name__ == "__main__":
    unittest.main()
