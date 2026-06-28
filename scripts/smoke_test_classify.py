import sys
import os
 
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
 
from monitor.packet_capture import PacketCapture
from monitor.traffic_classifier import TrafficClassifier
 
classifier = TrafficClassifier()
 
 
def handle_packet(metadata):
    result = classifier.extract_metadata(metadata)
 
    # Highlight insecure traffic so it's easy to spot in the terminal
    marker = "  <<< INSECURE" if result["classification"] == "INSECURE" else ""
 
    print(
        f"[{result['timestamp']}] "
        f"{result['source_ip']} -> {result['destination_ip']} "
        f"| {result['protocol']} "
        f"| port={result['destination_port']} "
        f"| {result['classification']}{marker}"
    )
 
 
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sudo venv/bin/python3 scripts/smoke_test_classify.py <interface_name>")
        sys.exit(1)
 
    interface = sys.argv[1]
    print(f"Starting capture + classification on interface: {interface}")
    print("Press Ctrl+C to stop.\n")
 
    capture = PacketCapture(interface=interface)
 
    try:
        capture.start_capture(on_packet_callback=handle_packet)
    except KeyboardInterrupt:
        capture.stop_capture()
        print("\nCapture stopped.")
    except PermissionError:
        print("\nPermission denied. Try running with sudo.")
 
