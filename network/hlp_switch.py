from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost, Host
from mininet.link import TCLink
from mininet.log import setLogLevel, info
import time
import datetime
from scapy.all import Ether, UDP, Raw, sendp
import socket
from health_switch import HealthMonitoringSwitch


def build_payload(is_switch, mac, port_stats, timestamp):

    header_lines = []
    header_lines.append("PACKET STARTED")
    header_lines.append(f"Is Switch: {is_switch}")
    header_lines.append(f"MAC: {mac}")
    header_lines.append(f"Number of Ports: {len(port_stats)}")
    header_lines.append("Timestamp: " + timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3])
    
    port_lines = []
    for port in port_stats:
        port_lines.append(
            f"""Port {port['port_id']}: Rxpkts={port['rxpkts']}, Rxbytes={port['rxbytes']}, Rxerrs={port['rxerrs']}, Txpkts={port['txpkts']}, Txbytes={port['txbytes']}, Txerrs={port['txerrs']}, rx_util={port["rx_utilization"]}, tx_util={port["tx_utilization"]}, throughput (mbps)={port["throughput (mbps)"]}, buffer_occ={port["buffer_occ"]}, """
        )
        # Calculate checksum
        if port["buffer_occ"] == None:
            port["buffer_occ"] = 0
        checksum = (
            port['rxpkts'] + port['rxbytes'] + port['rxerrs'] +
            port['txpkts'] + port['txbytes'] + port['txerrs'] +
            port['rx_utilization'] + port['tx_utilization'] +
            port['throughput (mbps)'] + port['buffer_occ']
        )
        # Perform checksum operation
        checksum = checksum % 65536  
        port_lines[-1] += f"Checksum={checksum}"
        
    footer = "PACKET ENDED"
    
    full_payload = "\n".join(header_lines + port_lines + [footer])
    return full_payload


class EnhancedSwitch:

    def __init__(self, host, switch, parameters):
        self.host = host      # Telemetry host
        self.switch = switch  # HealthMonitoringSwitch instance
        self.parameters = parameters

    def get_port_stats(self):
        """
        Retrieve real-time port statistics by calling the switch’s get_health_parameters().
        """
        health_data = self.switch.get_health_parameters(duration=1)
        port_stats = []
        for port, data in health_data.items():
            if "error" in data:
                continue
            port_stats.append({
                "port_id": port,
                "rxpkts": health_data[port]['rx_packet_rate'],
                "rxbytes": health_data[port]['rx_byte_rate'],
                "rxerrs": health_data[port]['rx_error_rate'],
                "txpkts": health_data[port]['tx_packet_rate'],
                "txbytes": health_data[port]['tx_byte_rate'],
                "txerrs": health_data[port]['tx_error_rate'],
                "rx_utilization": health_data[port]["rx_utilization"],
                "tx_utilization": health_data[port]["tx_utilization"],
                "throughput (mbps)": health_data[port]["throughput (mbps)"],
                "buffer_occ": health_data[port]["buffer_occupancy"]  
            })
        return port_stats


    def send_health_parameters(self, cc):
        """
        Build the custom readable payload and send it as a UDP packet using Scapy.
        """
        now = datetime.datetime.now()
        port_stats = self.get_port_stats()
        payload_str = build_payload(is_switch=True, mac=self.host.MAC(), port_stats=port_stats, timestamp=now)
        payload_bytes = payload_str.encode('ascii')
        
        iface = self.host.intfNames()[0]
        src_mac = self.host.MAC()
        dst_mac = cc.MAC()

        
        cmd = (
            'python3 -c "'
            "from scapy.all import Ether, UDP, Raw, sendp; "
            f"pkt = Ether(src='{src_mac}', dst='{dst_mac}')/UDP()/Raw(load={payload_bytes}); "
            f"sendp(pkt, iface='{iface}')"
            '"'
        )
        self.host.cmd(cmd)


