import datetime
import time
from scapy.all import Ether, UDP, Raw, sendp

# Import the HealthMonitoringFirewall class from your health_firewall.py
from health_firewall import HealthMonitoringFirewall

def build_firewall_health_payload(mac, health_data, timestamp):
    """
    Build a payload for firewall health telemetry.
    
    Format:
      FIREWALL PACKET STARTED
      MAC: <mac>
      Timestamp: YYYY-MM-DDTHH:mm:ss.SSS GMT
      For every interface (excluding overall keys):
          Interface <id>: Rxpkts: <data>, Rxbytes: <data>, Rxerrs: <data>, 
                            Txpkts: <data>, Txbytes: <data>, Txerrs: <data>, 
                            rx_util: <data>, tx_util: <data>, throughput (mbps): <data>, buffer_occ: <data>
      Overall CPU Usage: <data>
      Overall Memory Usage: <data>
      Aggregated Firewall Rule Stats: <data>
      FIREWALL PACKET ENDED
      Checksum: <checksum>
    """
    header_lines = []
    header_lines.append("FIREWALL PACKET STARTED")
    header_lines.append(f"MAC: {mac}")
    header_lines.append("Number of Interfaces: " + str(len(health_data.items())-3))
    header_lines.append("Timestamp: " + timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + " GMT")
    interface_lines = []
    for intf, data in health_data.items():
        # Skip overall metrics keys:
        if intf in ['cpu_usage_percent', 'memory_usage_percent', 'firewall_rule_stats']:
            continue
        if isinstance(data, dict):
            interface_lines.append(
                f"Interface {intf}: Rxpkts: {data.get('rx_packet_rate','N/A')}, "
                f"Rxbytes: {data.get('rx_byte_rate','N/A')}, "
                f"Rxerrs: {data.get('rx_error_rate','N/A')}, "
                f"Txpkts: {data.get('tx_packet_rate','N/A')}, "
                f"Txbytes: {data.get('tx_byte_rate','N/A')}, "
                f"Txerrs: {data.get('tx_error_rate','N/A')}, "
                f"rx_util: {data.get('rx_utilization','N/A')}, "
                f"tx_util: {data.get('tx_utilization','N/A')}, "
                f"throughput (mbps): {data.get('throughput (mbps)','N/A')}, "
                f"buffer_occ: {data.get('buffer_occupancy','N/A')}"
            )
    overall_lines = []
    overall_lines.append(f"CPU Usage: {health_data.get('cpu_usage_percent', 'N/A')}")
    overall_lines.append(f"Memory Usage: {health_data.get('memory_usage_percent', 'N/A')}")
    overall_lines.append(f"Aggregated Firewall Rule Stats: {health_data.get('firewall_rule_stats', 'N/A')}")
    
    footer = "FIREWALL PACKET ENDED"
    payload_without_checksum = "\n".join(header_lines + interface_lines + overall_lines + [footer])
    checksum_val = sum(ord(ch) for ch in payload_without_checksum) % 65536
    full_payload = payload_without_checksum + "\n" + f"Checksum: {checksum_val}"
    return full_payload

def build_firewall_rules_payload(mac, rule_details, timestamp):
    """
    Build a payload for detailed firewall rule data.
    
    Format:
      FIREWALL RULES PACKET STARTED
      MAC: <mac>
      Timestamp: YYYY-MM-DDTHH:mm:ss.SSS GMT
      Firewall Rules:
      <detailed firewall rule output>
      FIREWALL RULES PACKET ENDED
      Checksum: <checksum>
    """
    header_lines = []
    header_lines.append("FIREWALL RULES PACKET STARTED")
    header_lines.append(f"MAC: {mac}")
    header_lines.append("Timestamp: " + timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + " GMT")
    header_lines.append("Firewall Rules:")
    footer = "FIREWALL RULES PACKET ENDED"
    payload_without_checksum = "\n".join(header_lines) + "\n" + rule_details.strip() + "\n" + footer
    checksum_val = sum(ord(ch) for ch in payload_without_checksum) % 65536
    full_payload = payload_without_checksum + "\n" + f"Checksum: {checksum_val}"
    return full_payload

class EnhancedFirewall:
    """
    Custom class to handle telemetry for a firewall.
    Provides functions to send both overall health data and detailed firewall rules.
    """
    def __init__(self, firewall, parameters):
        """
        :param firewall: An instance of HealthMonitoringFirewall.
        :param parameters: A dictionary of parameters (if any).
        """
        self.firewall = firewall
        self.parameters = parameters

    def start(self):
        """
        Start the underlying firewall and initialize telemetry.
        """
        self.firewall.start()

    def get_health_data(self, duration=5):
        """
        Retrieve the health parameters from the firewall.
        """
        return self.firewall.get_health_parameters(duration=duration)

    def get_rule_details(self):
        """
        Retrieve the detailed firewall rules as a raw string.
        """
        return self.firewall.get_firewall_rules()

    def send_health_parameters(self, dest):
        """
        Package the firewall health data into a FIREWALL PACKET and send it to the destination.
        """
        now = datetime.datetime.utcnow()
        health_data = self.get_health_data(duration=1)
        payload_str = build_firewall_health_payload(self.firewall.MAC(), health_data, now)
        payload_bytes = payload_str.encode('ascii')
        iface = self.firewall.intfNames()[0]
        src_mac = self.firewall.MAC()
        dst_mac = dest.MAC()
        cmd = (
            'python3 -c "'
            "from scapy.all import Ether, UDP, Raw, sendp; "
            f"pkt = Ether(src='{src_mac}', dst='{dst_mac}')/UDP()/Raw(load={payload_bytes}); "
            f"sendp(pkt, iface='{iface}')"
            '"'
        )
        self.firewall.cmd(cmd)

    def send_rule_details(self, dest):
        """
        Package the detailed firewall rules into a FIREWALL RULES PACKET and send it to the destination.
        """
        now = datetime.datetime.utcnow()
        rule_details = self.get_rule_details()
        payload_str = build_firewall_rules_payload(self.firewall.MAC(), rule_details, now)
        payload_bytes = payload_str.encode('ascii')
        iface = self.firewall.intfNames()[0]
        src_mac = self.firewall.MAC()
        dst_mac = dest.MAC()
        cmd = (
            'python3 -c "'
            "from scapy.all import Ether, UDP, Raw, sendp; "
            f"pkt = Ether(src='{src_mac}', dst='{dst_mac}')/UDP()/Raw(load={payload_bytes}); "
            f"sendp(pkt, iface='{iface}')"
            '"'
        )
        self.firewall.cmd(cmd)
