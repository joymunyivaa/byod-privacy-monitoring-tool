"""
Unit tests for AlertEngine.

Uses a temporary database file for each test (not your real
data/alerts.db) so tests never pollute real monitoring data.

Run with:
    python3 -m unittest tests/test_alert_engine.py -v
"""

import unittest
import sys
import os
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from monitor.alert_engine import AlertEngine


class TestAlertEngine(unittest.TestCase):

    def setUp(self):
        """Creates a fresh temporary SQLite file for each test."""
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        self.engine = AlertEngine(db_path=self.temp_db.name)

    def tearDown(self):
        """Deletes the temporary database file after each test."""
        if os.path.exists(self.temp_db.name):
            os.remove(self.temp_db.name)

    def test_generate_alert_inserts_a_row(self):
        metadata = {
            "source_ip": "192.168.1.2",
            "destination_ip": "34.223.124.45",
            "protocol": "HTTP",
            "destination_port": 80,
            "timestamp": "2026-06-28T14:14:35.377271",
            "classification": "INSECURE",
        }
        alert_id = self.engine.generate_alert(metadata)
        self.assertIsInstance(alert_id, int)
        self.assertGreater(alert_id, 0)

    def test_get_alert_log_returns_inserted_record(self):
        metadata = {
            "source_ip": "192.168.1.2",
            "destination_ip": "34.223.124.45",
            "protocol": "HTTP",
            "destination_port": 80,
            "timestamp": "2026-06-28T14:14:35.377271",
            "classification": "INSECURE",
        }
        self.engine.generate_alert(metadata)
        log = self.engine.get_alert_log()

        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["source_ip"], "192.168.1.2")
        self.assertEqual(log[0]["protocol"], "HTTP")
        self.assertEqual(log[0]["destination_port"], 80)
        self.assertEqual(log[0]["classification"], "INSECURE")

    def test_get_alert_log_orders_newest_first(self):
        first = {"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2",
                  "protocol": "HTTP", "destination_port": 80,
                  "timestamp": "t1", "classification": "INSECURE"}
        second = {"source_ip": "3.3.3.3", "destination_ip": "4.4.4.4",
                   "protocol": "FTP", "destination_port": 21,
                   "timestamp": "t2", "classification": "INSECURE"}

        self.engine.generate_alert(first)
        self.engine.generate_alert(second)

        log = self.engine.get_alert_log()
        self.assertEqual(log[0]["source_ip"], "3.3.3.3")  # most recent first
        self.assertEqual(log[1]["source_ip"], "1.1.1.1")

    def test_get_alert_log_respects_limit(self):
        for i in range(5):
            self.engine.generate_alert({
                "source_ip": f"10.0.0.{i}", "destination_ip": "1.1.1.1",
                "protocol": "HTTP", "destination_port": 80,
                "timestamp": f"t{i}", "classification": "INSECURE"
            })

        log = self.engine.get_alert_log(limit=2)
        self.assertEqual(len(log), 2)

    def test_get_alert_count(self):
        self.assertEqual(self.engine.get_alert_count(), 0)

        self.engine.generate_alert({
            "source_ip": "1.1.1.1", "destination_ip": "2.2.2.2",
            "protocol": "HTTP", "destination_port": 80,
            "timestamp": "t1", "classification": "INSECURE"
        })

        self.assertEqual(self.engine.get_alert_count(), 1)

    def test_get_count_by_protocol(self):
        self.engine.generate_alert({
            "source_ip": "1.1.1.1", "destination_ip": "2.2.2.2",
            "protocol": "HTTP", "destination_port": 80,
            "timestamp": "t1", "classification": "INSECURE"
        })
        self.engine.generate_alert({
            "source_ip": "3.3.3.3", "destination_ip": "4.4.4.4",
            "protocol": "FTP", "destination_port": 21,
            "timestamp": "t2", "classification": "INSECURE"
        })
        self.engine.generate_alert({
            "source_ip": "5.5.5.5", "destination_ip": "6.6.6.6",
            "protocol": "HTTP", "destination_port": 80,
            "timestamp": "t3", "classification": "INSECURE"
        })

        self.assertEqual(self.engine.get_count_by_protocol("HTTP"), 2)
        self.assertEqual(self.engine.get_count_by_protocol("FTP"), 1)
        self.assertEqual(self.engine.get_count_by_protocol("Telnet"), 0)

    def test_table_created_automatically_on_init(self):
        # If we got this far without an exception in setUp(), the table
        # was created successfully. This test just makes that explicit.
        log = self.engine.get_alert_log()
        self.assertEqual(log, [])


if __name__ == "__main__":
    unittest.main()
