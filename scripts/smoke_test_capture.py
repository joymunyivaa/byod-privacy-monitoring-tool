import sys
import os
 
# Allow running this script directly without installing the package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
 
from monitor.packet_capture import PacketCapture
 
 
def print_packet(metadata):
    print(
        f"[{metadata['timestamp']}] "
        f"{metadata['source_ip']} -> {metadata['destination_ip']} "
        f"| protocol={metadata['protocol']} "
        f"| port={metadata['destination_port']}"
    )
 
 
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sudo python3 scripts/smoke_test_capture.py <interface_name>")
        sys.exit(1)
 
    interface = sys.argv[1]
    print(f"Starting capture on interface: {interface}")
    print("Press Ctrl+C to stop.\n")
 
    capture = PacketCapture(interface=interface)
 
    try:
        capture.start_capture(on_packet_callback=print_packet)
    except KeyboardInterrupt:
        capture.stop_capture()
        print("\nCapture stopped.")
    except PermissionError:
        print("\nPermission denied. Try running with sudo.")
    except Exception as e:
        print(f"\nError: {e}")
 
