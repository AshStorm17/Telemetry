from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost, Host
from mininet.link import TCLink
from mininet.log import setLogLevel, info
import time
import datetime
from scapy.all import Ether, UDP, Raw, sendp
import socket
from health_router import HealthMonitoringRouter


# Payload Building Function
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
        checksum %= 65536 
        interface_lines[-1] += f"Checksum={checksum}"
        
    footer = "PACKET ENDED"
    
    full_payload = "\n".join(header_lines + interface_lines + [footer])
    return full_payload

def build_router_payload(mac, routing_info, timestamp):
    header_lines = []
    header_lines.append("ROUTER PACKET STARTED")
    header_lines.append(f"MAC: {mac}")
    num_routes = len(routing_info.get("routing_table", []))
    header_lines.append(f"Number of Routes: {num_routes}")
    header_lines.append("Timestamp: " + timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + " GMT")
    
    route_lines = []
    for entry in routing_info.get("routing_table", []):
        destination = entry.get("destination", "N/A")
        gateway = entry.get("gateway", "N/A")
        device = entry.get("device", "N/A")
        protocol = entry.get("protocol", "N/A")
        scope = entry.get("scope", "N/A")
        src = entry.get("src", "N/A")
        route_lines.append(
            f"Route: Dest: {destination}, Gateway: {gateway}, Dev: {device}, Proto: {protocol}, Scope: {scope}, Src: {src}"
        )

    footer = "ROUTER PACKET ENDED"
    payload_without_checksum = "\n".join(header_lines + route_lines + [footer])
    checksum_val = sum(ord(char) for char in payload_without_checksum) % 65536
    full_payload = payload_without_checksum + "\n" + f"Checksum: {checksum_val}"
    return full_payload


# --- Enhanced Router Class Using Health Parameters ---
class EnhancedRouter:

    def __init__(self, router, parameters):
        self.router = router  
        self.parameters = parameters

    def start(self):
        self.router.start()
    
    def get_interface_stats(self):
        health_data = self.router.get_health_parameters(duration=1)
        interface_stats = []
        for intf, data in health_data.items():
            # We only process keys that hold interface statistics (i.e. a dict with expected fields)
            if not isinstance(data, dict):
                continue
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
        now = datetime.datetime.now()
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

    def send_routing_parameters(self, cc):
        now = datetime.datetime.now()
        routing_info = self.router.get_routing_information()
        payload_str = build_router_payload(mac=self.router.MAC(), routing_info=routing_info, timestamp=now)
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
