from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost, Host
from mininet.link import TCLink
from mininet.log import setLogLevel, info
import time
import datetime
from scapy.all import Ether, UDP, Raw, sendp
import socket

# Import the HealthMonitoringRouter from our router module
from health_router import HealthMonitoringRouter


# --- Payload Building Function (Readable Version) ---
def build_payload(is_switch, mac, interface_stats, timestamp):
    header_lines = []
    header_lines.append("PACKET STARTED")
    header_lines.append(f"Is Switch: {is_switch}")
    header_lines.append(f"MAC: {mac}")
    header_lines.append(f"Number of Interfaces: {len(interface_stats)}")
    header_lines.append("Timestamp: " + timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3])
    
    interface_lines = []
    for intf in interface_stats:
        interface_lines.append(
            f"Interface {intf['interface_id']}: Rxpkts={intf['rxpkts']}, Rxbytes={intf['rxbytes']}, Rxerrs={intf['rxerrs']}, "
            f"Txpkts={intf['txpkts']}, Txbytes={intf['txbytes']}, Txerrs={intf['txerrs']}, "
            f"rx_util={intf['rx_utilization']}, tx_util={intf['tx_utilization']}, throughput (mbps)={intf['throughput (mbps)']}, "
            f"buffer_occ={intf['buffer_occ']}, "
        )
        # Calculate checksum
        checksum = (
            intf['rxpkts'] + intf['rxbytes'] + intf['rxerrs'] +
            intf['txpkts'] + intf['txbytes'] + intf['txerrs'] +
            intf['rx_utilization'] + intf['tx_utilization'] +
            intf['throughput (mbps)'] + intf['buffer_occ']
        )
        checksum %= 65536  # Ensure checksum is within 16-bit range
        interface_lines[-1] += f"Checksum={checksum}"
        
    footer = "PACKET ENDED"
    
    # Combine all parts with newlines
    full_payload = "\n".join(header_lines + interface_lines + [footer])
    return full_payload


# --- Enhanced Router Class Using Health Parameters ---
class EnhancedRouter:
    """
    Custom class to handle telemetry for a router.
    Uses live health parameters from the associated HealthMonitoringRouter.
    """
    def __init__(self, router, parameters):
        self.router = router  # HealthMonitoringRouter instance
        self.parameters = parameters

    def get_interface_stats(self):
        """
        Retrieve real-time interface statistics by calling the router's get_health_parameters().
        Then map them to a readable text format.
        """
        health_data = self.router.get_health_parameters(duration=1)
        interface_stats = []
        # health_data is a dict keyed by interface names (and possibly system parameters)
        for intf, data in health_data.items():
            # We only process keys that hold interface statistics (i.e. a dict with expected fields)
            if not isinstance(data, dict):
                continue
            # Look for a key unique to an interface record.
            if 'rx_packet_rate' in data:
                interface_stats.append({
                    "interface_id": intf,
                    "rxpkts": data['rx_packet_rate'],
                    "rxbytes": data['rx_byte_rate'],
                    "rxerrs": data['rx_error_rate'],
                    "txpkts": data['tx_packet_rate'],
                    "txbytes": data['tx_byte_rate'],
                    "txerrs": data['tx_error_rate'],
                    "rx_utilization": data["rx_utilization"],
                    "tx_utilization": data["tx_utilization"],
                    "throughput (mbps)": data["throughput (mbps)"],
                    "buffer_occ": data["buffer_occupancy"]
                })
        return interface_stats

    def send_health_parameters(self, cc):
        """
        Build the custom readable payload and send it as a UDP packet using Scapy,
        encapsulated in an Ethernet frame.
        """
        now = datetime.datetime.utcnow()
        interface_stats = self.get_interface_stats()
        # Build the payload; mark is_switch as False for a router.
        payload_str = build_payload(is_switch=False, mac=self.router.MAC(), interface_stats=interface_stats, timestamp=now)
        # Encode as ASCII bytes
        payload_bytes = payload_str.encode('ascii')
        
        iface = self.router.intfNames()[0]
        src_mac = self.router.MAC()
        dst_mac = cc.MAC()
        
        cmd = (
            'python3 -c "'
            "from scapy.all import Ether, UDP, Raw, sendp; "
            f"pkt = Ether(src='{src_mac}', dst='{dst_mac}')/UDP()/Raw(load={payload_bytes}); "
            f"sendp(pkt, iface='{iface}')"
            '"'
        )
        self.router.cmd(cmd)
