class TrafficClassifier:
    """
    Classifies packet metadata as SECURE or INSECURE based on
    destination port and protocol.
 
    Attributes:
        insecure_ports (dict): Maps known insecure port numbers to the
            protocol name they correspond to, e.g. {80: "HTTP"}.
    """
 
    def __init__(self):
        # Port -> protocol name, for the protocols this study targets
        # (Chapter 1, Scope: HTTP, FTP, Telnet)
        self.insecure_ports = {
            80: "HTTP",
            20: "FTP",
            21: "FTP",
            23: "Telnet",
        }
 
    def classify_packet(self, metadata: dict) -> str:
        """
        Returns 'INSECURE' if the packet's destination port matches a
        known insecure protocol port, otherwise 'SECURE'.
 
        Args:
            metadata (dict): Packet metadata as produced by
                PacketCapture.get_packet_metadata().
 
        Returns:
            str: 'INSECURE' or 'SECURE'
        """
        port = metadata.get("destination_port")
 
        if port in self.insecure_ports:
            return "INSECURE"
 
        return "SECURE"
 
    def get_protocol_name(self, metadata: dict) -> str:
        """
        Returns the human-readable protocol name (e.g. 'HTTP', 'FTP',
        'Telnet') if the port matches a known insecure protocol.
        Falls back to the raw transport protocol (TCP/UDP/OTHER) if
        it's not one of the targeted insecure protocols.
 
        Args:
            metadata (dict): Packet metadata.
 
        Returns:
            str: Protocol label to display/store.
        """
        port = metadata.get("destination_port")
        return self.insecure_ports.get(port, metadata.get("protocol", "OTHER"))
 
    def extract_metadata(self, metadata: dict) -> dict:
        """
        Builds the final metadata dictionary that will be handed to
        AlertEngine, enriching it with the classification label and
        resolved protocol name.
 
        Args:
            metadata (dict): Raw packet metadata from PacketCapture.
 
        Returns:
            dict: {
                'source_ip': str,
                'destination_ip': str,
                'destination_port': int or None,
                'protocol': str,            # resolved name, e.g. 'HTTP'
                'timestamp': str,
                'classification': str       # 'SECURE' or 'INSECURE'
            }
        """
        classification = self.classify_packet(metadata)
        protocol_name = self.get_protocol_name(metadata)
 
        return {
            "source_ip": metadata.get("source_ip"),
            "destination_ip": metadata.get("destination_ip"),
            "destination_port": metadata.get("destination_port"),
            "protocol": protocol_name,
            "timestamp": metadata.get("timestamp"),
            "classification": classification,
        }
 
