from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
 
 
class PacketCapture:
    """
    Captures live packets on a given network interface.
 
    Attributes:
        interface (str): Name of the network interface to listen on
                          (e.g. 'eth0', 'wlan0', 'lo').
        is_running (bool): Tracks whether a capture session is active.
    """
 
    def __init__(self, interface: str):
        self.interface = interface
        self.is_running = False
        self._on_packet_callback = None
 
    def start_capture(self, on_packet_callback):
        """
        Starts a blocking capture session on the configured interface.
 
        Args:
            on_packet_callback (callable): A function that will be called
                with each captured packet's extracted header info (a dict).
                This is how PacketCapture hands packets off to whatever
                is listening (in our case, TrafficClassifier).
        """
        self.is_running = True
        self._on_packet_callback = on_packet_callback
 
        # sniff() blocks until stop_filter returns True, or KeyboardInterrupt
        sniff(
            iface=self.interface,
            prn=self._handle_packet,
            stop_filter=lambda pkt: not self.is_running,
            store=False  # CRITICAL: never buffer payloads in memory
        )
 
    def stop_capture(self):
        """Signals the capture loop to stop on the next packet check."""
        self.is_running = False
 
    def _handle_packet(self, packet):
        """
        Internal callback passed to Scapy's sniff(). Extracts only the
        metadata we need (no payload) and forwards it to the registered
        callback as a plain dictionary.
        """
        metadata = self.get_packet_metadata(packet)
        if metadata and self._on_packet_callback:
            self._on_packet_callback(metadata)
 
    @staticmethod
    def get_packet_metadata(packet):
        """
        Extracts header-level metadata from a raw Scapy packet.
        Returns None if the packet has no IP layer (i.e. not routable
        traffic we care about).
 
        Returns:
            dict: {
                'source_ip': str,
                'destination_ip': str,
                'destination_port': int or None,
                'protocol': str,   # 'TCP', 'UDP', or 'OTHER'
                'timestamp': str (ISO format)
            }
        """
        if not packet.haslayer(IP):
            return None
 
        ip_layer = packet[IP]
        source_ip = ip_layer.src
        destination_ip = ip_layer.dst
 
        destination_port = None
        protocol = "OTHER"
 
        if packet.haslayer(TCP):
            protocol = "TCP"
            destination_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol = "UDP"
            destination_port = packet[UDP].dport
 
        return {
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "destination_port": destination_port,
            "protocol": protocol,
            "timestamp": datetime.now().isoformat()
        }
 
