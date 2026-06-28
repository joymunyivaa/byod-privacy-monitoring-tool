"""
Standalone smoke test for the Dashboard, with no live packet capture.
Inserts a couple of fake alerts so you can see the table populated,
then starts the Flask server so you can view it in a browser.

Usage:
    venv/bin/python3 scripts/smoke_test_dashboard.py

Then open a browser to http://<your-kali-ip>:5000
Press Ctrl+C to stop.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from monitor.alert_engine import AlertEngine
from monitor.dashboard import Dashboard

if __name__ == "__main__":
    engine = AlertEngine(db_path="data/alerts.db")

    # Insert a couple of fake alerts just to see the table populated
    engine.generate_alert({
        "source_ip": "192.168.1.2",
        "destination_ip": "34.223.124.45",
        "protocol": "HTTP",
        "destination_port": 80,
        "timestamp": "2026-06-28T14:14:35",
        "classification": "INSECURE",
    })
    engine.generate_alert({
        "source_ip": "192.168.1.4",
        "destination_ip": "10.0.0.5",
        "protocol": "FTP",
        "destination_port": 21,
        "timestamp": "2026-06-28T14:15:01",
        "classification": "INSECURE",
    })

    dashboard = Dashboard(alert_engine=engine, host="0.0.0.0", port=5000)

    print("Dashboard running. Open http://<your-kali-ip>:5000 in a browser.")
    print("Press Ctrl+C to stop.")
    dashboard.start_dashboard()

