"""
Connection-Level Accuracy Calculator
---------------------------------------
Reads alert records from the SQLite database and groups packets into
distinct "connection sessions" per protocol, using a time-gap threshold.
If the gap between two consecutive packets of the same protocol exceeds
GAP_THRESHOLD_SECONDS, they're considered separate connection attempts.

This gives a connection-level detection count that can be compared
against the known ground truth (the fixed number of curl/telnet calls
made by generate_test_traffic.py), producing a defensible accuracy
percentage for Chapter 5.

Usage:
    venv/bin/python3 scripts/calculate_accuracy.py
"""

import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from monitor.alert_engine import AlertEngine

# If two packets of the same protocol are more than this many seconds
# apart, they're treated as belonging to separate connection attempts.
GAP_THRESHOLD_SECONDS = 0.5

# Ground truth from generate_test_traffic.py
EXPECTED_CONNECTIONS = {
    "HTTP": 10,
    "FTP": 5,
    "Telnet": 5,
}


def count_sessions(timestamps, gap_threshold):
    """
    Given a sorted list of datetime objects for one protocol, returns
    the number of distinct sessions (groups separated by gaps larger
    than gap_threshold seconds).
    """
    if not timestamps:
        return 0

    session_count = 1
    for i in range(1, len(timestamps)):
        gap = (timestamps[i] - timestamps[i - 1]).total_seconds()
        if gap > gap_threshold:
            session_count += 1

    return session_count


def main():
    engine = AlertEngine(db_path="data/alerts.db")
    all_alerts = engine.get_alert_log(limit=10000)

    # Group timestamps by protocol
    by_protocol = {}
    for alert in all_alerts:
        protocol = alert["protocol"]
        ts = datetime.fromisoformat(alert["timestamp"])
        by_protocol.setdefault(protocol, []).append(ts)

    print("=" * 70)
    print("CONNECTION-LEVEL DETECTION ACCURACY")
    print(f"(gap threshold: {GAP_THRESHOLD_SECONDS}s)")
    print("=" * 70)

    total_expected = 0
    total_detected = 0

    for protocol, expected in EXPECTED_CONNECTIONS.items():
        timestamps = sorted(by_protocol.get(protocol, []))
        detected_sessions = count_sessions(timestamps, GAP_THRESHOLD_SECONDS)
        packet_count = len(timestamps)

        accuracy = (min(detected_sessions, expected) / expected * 100) if expected else 0

        print(f"\n{protocol}:")
        print(f"  Expected connection attempts : {expected}")
        print(f"  Detected sessions            : {detected_sessions}")
        print(f"  Total packets captured       : {packet_count}")
        print(f"  Avg packets per session       : {packet_count / detected_sessions:.1f}" if detected_sessions else "  N/A")
        print(f"  Session-level accuracy        : {accuracy:.1f}%")

        total_expected += expected
        total_detected += min(detected_sessions, expected)

    overall_accuracy = (total_detected / total_expected * 100) if total_expected else 0

    print("\n" + "=" * 70)
    print(f"OVERALL: {total_detected} / {total_expected} insecure connection attempts detected")
    print(f"OVERALL DETECTION ACCURACY: {overall_accuracy:.1f}%")
    print("=" * 70)


if __name__ == "__main__":
    main()

