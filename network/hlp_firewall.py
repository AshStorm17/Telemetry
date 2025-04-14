from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost, Host
from mininet.link import TCLink
from mininet.log import setLogLevel, info
import time
import datetime
from scapy.all import Ether, UDP, Raw, sendp
import socket

# Import the HealthMonitoringFirewall class from your health_firewall module
from health_firewall import HealthMonitoringFirewall


# --- Payload Building Function for Firewall Health Parameters ---
def build_firewall_payload(mac, health_data, timestamp):
    """
    Constructs a payload string containing health metrics for the firewall.
    
    The payload includes:
      - A header with the firewall MAC and timestamp.
      - For each interface, rate and utilization metrics.
      - A summary of the firewall-specific statistics (iptables counters),
        along with CPU and memory usage.
      - A footer to mark the end of the packet.
    """
    header_lines = []
    header_lines.append("FIREWALL PACKET STARTED")
    header_lines.append(f"MAC: {mac}")
    header_lines.append("Timestamp: " + timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3])
    header_lines.append("")  # Blank line for readability
    
    interface_lines = []
    # Iterate over health_data keys that represent interface stats.
    for key, data in health_data.items():
        if key in ['firewall_rules', 'cpu_usage_percent', 'memory_usage_percent']:
            continue
        if isinstance(data, dict):
            interface_lines.append(
                f"Interface {key}: RX {data.get('rx_packet_rate', 'N/A')} pkt/s, TX {data.get('tx_packet_rate', 'N/A')} pkt/s, "
                f"RX_util {data.get('rx_utilization', 'N/A')}%, TX_util {data.get('tx_utilization', 'N/A')}%, "
                f"Throughput {data.get('throughput (mbps)', 'N/A')} Mbps, Buffer {data.get('buffer_occupancy', 'N/A')}, "
                f"RX_err {data.get('rx_error_rate', 'N/A')}, TX_err {data.get('tx_error_rate', 'N/A')}"
            )
    
    summary_lines = []
    firewall_rules = health_data.get("firewall_rules", {})
    cpu_usage = health_data.get("cpu_usage_percent", "N/A")
    memory_usage = health_data.get("memory_usage_percent", "N/A")
    summary_lines.append("")
    summary_lines.append("Firewall Rule Stats:")
    summary_lines.append(f"  Total Packets: {firewall_rules.get('total_firewall_packets', 'N/A')}, "
                         f"Total Bytes: {firewall_rules.get('total_firewall_bytes', 'N/A')}")
    summary_lines.append(f"CPU Usage: {cpu_usage}%, Memory Usage: {memory_usage}%")
    
    footer = "FIREWALL PACKET ENDED"
    
    full_payload = "\n".join(header_lines + interface_lines + summary_lines + [footer])
    return full_payload


# --- Enhanced Firewall Class Using Health Parameters ---
class EnhancedFirewall:
    """
    Custom class to handle telemetry for a firewall.
    Uses live health parameters from the associated HealthMonitoringFirewall.
    """
    def __init__(self, firewall, parameters):
        self.firewall = firewall  # An instance of HealthMonitoringFirewall
        self.parameters = parameters

    def get_health_data(self):
        """
        Retrieve real-time health metrics by calling the firewall's get_health_parameters.
        """
        # Use a short duration snapshot (e.g., 1 second)
        return self.firewall.get_health_parameters(duration=1)

    def send_firewall_parameters(self, dest):
        """
        Build the firewall payload using the health metrics and send it
        as a UDP packet (encapsulated in an Ethernet frame) to the destination.
        
        :param dest: The destination host object (e.g., a cluster center) with a valid MAC.
        """
        now = datetime.datetime.utcnow()
        health_data = self.get_health_data()
        payload_str = build_firewall_payload(mac=self.firewall.MAC(), health_data=health_data, timestamp=now)
        payload_bytes = payload_str.encode('ascii')
        
        # Select the first interface for sending (adjust if needed)
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
