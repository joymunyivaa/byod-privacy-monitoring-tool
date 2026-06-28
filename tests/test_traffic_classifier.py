import unittest
import sys
import os
 
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
 
from monitor.traffic_classifier import TrafficClassifier
 
 
class TestTrafficClassifier(unittest.TestCase):
 
    def setUp(self):
        """Runs before every test method — gives each test a fresh classifier."""
        self.classifier = TrafficClassifier()
 
    def test_http_port_is_insecure(self):
        metadata = {"destination_port": 80, "protocol": "TCP"}
        result = self.classifier.classify_packet(metadata)
        self.assertEqual(result, "INSECURE")
 
    def test_ftp_control_port_is_insecure(self):
        metadata = {"destination_port": 21, "protocol": "TCP"}
        result = self.classifier.classify_packet(metadata)
        self.assertEqual(result, "INSECURE")
 
    def test_ftp_data_port_is_insecure(self):
        metadata = {"destination_port": 20, "protocol": "TCP"}
        result = self.classifier.classify_packet(metadata)
        self.assertEqual(result, "INSECURE")
 
    def test_telnet_port_is_insecure(self):
        metadata = {"destination_port": 23, "protocol": "TCP"}
        result = self.classifier.classify_packet(metadata)
        self.assertEqual(result, "INSECURE")
 
    def test_https_port_is_secure(self):
        metadata = {"destination_port": 443, "protocol": "TCP"}
        result = self.classifier.classify_packet(metadata)
        self.assertEqual(result, "SECURE")
 
    def test_dns_port_is_secure(self):
        # DNS (53) isn't one of our targeted insecure protocols (scope: HTTP/FTP/Telnet)
        metadata = {"destination_port": 53, "protocol": "UDP"}
        result = self.classifier.classify_packet(metadata)
        self.assertEqual(result, "SECURE")
 
    def test_none_port_is_secure(self):
        # Packets with no resolvable port (e.g. protocol=OTHER) shouldn't crash
        # and should default to SECURE since we can't confirm insecurity.
        metadata = {"destination_port": None, "protocol": "OTHER"}
        result = self.classifier.classify_packet(metadata)
        self.assertEqual(result, "SECURE")
 
    def test_get_protocol_name_resolves_http(self):
        metadata = {"destination_port": 80, "protocol": "TCP"}
        result = self.classifier.get_protocol_name(metadata)
        self.assertEqual(result, "HTTP")
 
    def test_get_protocol_name_falls_back_to_raw_protocol(self):
        metadata = {"destination_port": 443, "protocol": "TCP"}
        result = self.classifier.get_protocol_name(metadata)
        self.assertEqual(result, "TCP")
 
    def test_extract_metadata_returns_full_record(self):
        metadata = {
            "source_ip": "192.168.1.2",
            "destination_ip": "192.168.1.5",
            "destination_port": 21,
            "protocol": "TCP",
            "timestamp": "2026-06-28T14:00:00",
        }
        result = self.classifier.extract_metadata(metadata)
 
        self.assertEqual(result["source_ip"], "192.168.1.2")
        self.assertEqual(result["destination_ip"], "192.168.1.5")
        self.assertEqual(result["destination_port"], 21)
        self.assertEqual(result["protocol"], "FTP")
        self.assertEqual(result["classification"], "INSECURE")
        self.assertEqual(result["timestamp"], "2026-06-28T14:00:00")
 
 
if __name__ == "__main__":
    unittest.main()
 
