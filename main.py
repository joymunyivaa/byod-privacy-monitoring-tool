"""
main.py
--------
Entry point for the Real-Time Data-in-Transit Privacy Monitoring Tool.

Wires together the four core modules:
    PacketCapture     -> captures raw packets
    TrafficClassifier -> classifies each packet as SECURE / INSECURE
    AlertEngine       -> persists INSECURE detections to SQLite
    Dashboard         -> serves the Flask web UI showing real-time alerts

Packet capture and the Flask server both block, so capture runs on a
background thread while Flask runs on the main thread. The dashboard's
Start/Stop buttons control whether capture is actually running.

Usage:
    sudo venv/bin/python3 main.py <interface_name>

Example:
    sudo venv/bin/python3 main.py eth1

Open a browser to http://<kali-ip>:5000 to view the dashboard.
"""

import sys
import threading

from monitor.packet_capture import PacketCapture
from monitor.traffic_classifier import TrafficClassifier
from monitor.alert_engine import AlertEngine
from monitor.dashboard import Dashboard


class MonitoringApp:
    """
    Coordinates PacketCapture, TrafficClassifier, AlertEngine, and
    Dashboard so they work together as a single running system.
    """

    def __init__(self, interface: str):
        self.classifier = TrafficClassifier()
        self.alert_engine = AlertEngine(db_path="data/alerts.db")
        self.capture = PacketCapture(interface=interface)
        self.dashboard = Dashboard(alert_engine=self.alert_engine, host="0.0.0.0", port=5000)

        self.capture_thread = None

        # Wire the dashboard's Start/Stop buttons to actually control capture
        self.dashboard.set_start_callback(self._start_capture_thread)
        self.dashboard.set_stop_callback(self._stop_capture_thread)

    def _handle_packet(self, metadata: dict):
        """
        Called by PacketCapture for every captured packet. Classifies
        it, and if insecure, generates and persists an alert.
        """
        result = self.classifier.extract_metadata(metadata)

        if result["classification"] == "INSECURE":
            self.alert_engine.generate_alert(result)
            print(
                f"[ALERT] {result['source_ip']} -> {result['destination_ip']} "
                f"| {result['protocol']} | port={result['destination_port']}"
            )

    def _start_capture_thread(self):
        """Starts packet capture on a background thread so it doesn't
        block the Flask server running on the main thread."""
        if self.capture_thread and self.capture_thread.is_alive():
            return  # already running

        self.capture_thread = threading.Thread(
            target=self.capture.start_capture,
            kwargs={"on_packet_callback": self._handle_packet},
            daemon=True  # thread dies automatically if main program exits
        )
        self.capture_thread.start()
        print("Packet capture started.")

    def _stop_capture_thread(self):
        """Signals the capture loop to stop."""
        self.capture.stop_capture()
        print("Packet capture stopped.")

    def run(self):
        """Starts the Flask dashboard (blocking call on the main thread)."""
        print(f"Dashboard starting on http://0.0.0.0:5000")
        print("Use the Start/Stop buttons on the dashboard to control monitoring.")
        self.dashboard.start_dashboard()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sudo venv/bin/python3 main.py <interface_name>")
        print("Example: sudo venv/bin/python3 main.py eth1")
        sys.exit(1)

    interface = sys.argv[1]
    app = MonitoringApp(interface=interface)
    app.run()
