from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost, Host
from mininet.link import TCLink
from mininet.log import setLogLevel, info
import time
import datetime
from scapy.all import Ether, UDP, Raw, sendp
import socket

# Import the HealthMonitoringSwitch from our separate module
from health_switch import HealthMonitoringSwitch
from packet_processor import end2end_cc2dc

# --- Payload Building Function (Readable Version) ---
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
            f"Port {port['port_id']}: Rxpkts={port['rxpkts']}, Rxbytes={port['rxbytes']}, "
            f"Rxerrs={port['rxerrs']}, Txpkts={port['txpkts']}, Txbytes={port['txbytes']}, Txerrs={port['txerrs']}, "
            f"rx_util={port["rx_utilization"]}, tx_util={port["tx_utilization"]}, throughput (mbps)={port["throughput (mbps)"]}, "
            f"buffer_occ={port["buffer_occ"]}"
        )
    
    footer = "PACKET ENDED"
    
    # Combine all parts with newlines
    full_payload = "\n".join(header_lines + port_lines + [footer])
    return full_payload

# --- Enhanced Switch Class Using Health Parameters ---
class EnhancedSwitch:
    """
    Custom class to handle telemetry for a switch.
    Uses live health parameters from the associated HealthMonitoringSwitch.
    """
    def __init__(self, host, switch, parameters):
        self.host = host      # Telemetry host
        self.switch = switch  # HealthMonitoringSwitch instance
        self.parameters = parameters

    def get_port_stats(self):
        """
        Retrieve real-time port statistics by calling the switch’s get_health_parameters().
        Then map them to a readable text format.
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
        Build the custom readable payload and send it as a UDP packet using Scapy,
        encapsulated in an Ethernet frame.
        """
        now = datetime.datetime.utcnow()
        port_stats = self.get_port_stats()
        # Build the payload
        payload_str = build_payload(is_switch=True, mac=self.host.MAC(), port_stats=port_stats, timestamp=now)
        # Encode as ASCII bytes
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

# --- Topology Definition ---
class CustomTopo(Topo):
    """
    Topology with a HealthMonitoringSwitch (s1) and an attached telemetry host (s1h).
    Other hosts: h1, cc (cluster center), h2.
    """
    def build(self, n=3):
        s1 = self.addSwitch('s1', cls=HealthMonitoringSwitch)
        s1h = self.addHost('s1h')
        h1 = self.addHost('h1')
        cc = self.addHost('cc')
        h2 = self.addHost('h2')
        self.addLink(s1h, s1,max_queue_size = 200)
        self.addLink(h1, s1,max_queue_size = 200)
        self.addLink(cc, s1,max_queue_size = 200)
        self.addLink(h2, s1,max_queue_size = 200)

def simpleTest():
    # Create the topology and network
    topo = CustomTopo(n=3)
    net = Mininet(topo=topo, host=Host, link=TCLink)
    net.start()
    
    # Retrieve nodes
    s1 = net.get('s1')
    s1.capture_initial_stats()  # Capture initial stats for rate calculation
    s1h = net.get('s1h')
    h1 = net.get('h1')
    cc = net.get('cc')
    h2 = net.get('h2')


    # Generate some traffic between h1 and h2 (to produce non-zero counters)
    h2.cmd('iperf -s -u -i 1 > iperf_server_output &')
    time.sleep(1)
    h1.cmd('iperf -c ' + h2.IP() + ' -u -t 3000 -b 30m &')
    time.sleep(1)

    # Capture all packets excluding ICMP, MDNS, and ARP
    cc.cmd('tcpdump -i any -v -w all_packets.pcap not icmp6 and not port 5353 and not arp &')

    # Create an EnhancedSwitch instance (telemetry host + monitoring switch)
    enhanced_switch = EnhancedSwitch(s1h, s1, parameters={})
    
    try:
        # Send telemetry packets continuously in an infinite loop
        while True:
            enhanced_switch.send_health_parameters(cc)
            time.sleep(4)
    except KeyboardInterrupt:
        print("Infinite telemetry loop interrupted by user.")
    finally:
        # Cleanup: kill background processes and process the captured packets
        cc.cmd("killall tcpdump")
        h2.cmd("killall iperf")
        end2end_cc2dc("all_packets.pcap", "cc1")
        net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    simpleTest()
