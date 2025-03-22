from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost, Host
from mininet.link import TCLink
from mininet.log import setLogLevel, info
import time
import datetime
from scapy import *
from scapy.all import *
import socket

# Import the HealthMonitoringSwitch from our separate module
from health_switch import HealthMonitoringSwitch

# --- Bit-Packing and Payload Building Functions ---
def pack_fields(fields):
    """
    Pack a list of (value, n_bits) tuples into a bytes object.
    """
    total_bits = sum(bits for _, bits in fields)
    packed_int = 0
    for val, bits in fields:
        packed_int = (packed_int << bits) | (val & ((1 << bits) - 1))
    num_bytes = (total_bits + 7) // 8
    return packed_int.to_bytes(num_bytes, byteorder='big')

def build_payload(is_switch, mac, port_stats, timestamp):
    """
    Build the payload according to your protocol design, with
    ASCII markers at the start and end: "PACKET STARTED" / "PACKET ENDED".
      Header:
        1 bit: Switch/Router flag
        48 bits: MAC Address
        4 bits: Number of ports
        Timestamp broken into:
          - Year offset (YYYY-2000): 8 bits
          - Month: 4 bits
          - Day: 5 bits
          - Hour: 5 bits
          - Minute: 8 bits
          - Second: 8 bits
          - Millisecond: 10 bits
      For each port (516 bits per port):
        16 bits: Port ID
        50 bits each for: Rxpkts, Rxbytes, Rxdrop, Rxerrs, Rxcrc, Txpkts, Txbytes, Txdrop, Txerrs, Txcoll
    """
    fields = []
    # 1) Flag: 1 bit (1 for switch)
    fields.append((1 if is_switch else 0, 1))

    # 2) MAC Address: 48 bits
    mac_int = int(mac.replace(":", ""), 16)
    fields.append((mac_int, 48))

    # 3) Number of ports: 4 bits
    num_ports = len(port_stats)
    fields.append((num_ports, 4))

    # 4) Timestamp (48 bits total)
    year_field = timestamp.year - 2000
    fields.append((year_field, 8))      # year offset
    fields.append((timestamp.month, 4))
    fields.append((timestamp.day, 5))
    fields.append((timestamp.hour, 5))
    fields.append((timestamp.minute, 8))
    fields.append((timestamp.second, 8))
    millisecond = int(timestamp.microsecond / 1000)
    fields.append((millisecond, 10))

    # 5) Per-port stats (516 bits per port)
    for port in port_stats:
        fields.append((port["port_id"], 16))
        fields.append((port["rxpkts"], 50))
        fields.append((port["rxbytes"], 50))
        fields.append((0, 50))  # rxdrop placeholder
        fields.append((port["rxerrs"], 50))
        fields.append((0, 50))  # rxcrc placeholder
        fields.append((port["txpkts"], 50))
        fields.append((port["txbytes"], 50))
        fields.append((0, 50))  # txdrop placeholder
        fields.append((port["txerrs"], 50))
        fields.append((0, 50))  # txcoll placeholder

    # Pack the fields into a binary payload
    payload = pack_fields(fields)

    # Add ASCII prefix and suffix
    prefix = b"PACKET STARTED"
    suffix = b"PACKET ENDED"

    # Combine them
    final_payload = prefix + payload + suffix
    return final_payload

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
        Then map them to the fields required by our bit-packed protocol.
        """
        health_data = self.switch.get_health_parameters(duration=1)
        port_stats = []
        for port, data in health_data.items():
            if "error" in data:
                continue
            port_stats.append({
                "port_id": port,
                "rxpkts": int(data.get('rx_packet_rate', 0)),
                "rxbytes": int(data.get('rx_byte_rate', 0)),
                "rxdrop": 0,  # placeholders
                "rxerrs": int(data.get('rx_error_rate', 0)),
                "rxcrc": 0,
                "txpkts": int(data.get('tx_packet_rate', 0)),
                "txbytes": int(data.get('tx_byte_rate', 0)),
                "txdrop": 0,
                "txerrs": int(data.get('tx_error_rate', 0)),
                "txcoll": 0
            })
        return port_stats

    def send_health_parameters(self, cc):
        """
        Build the custom payload (with ASCII markers) and send it
        as a UDP packet using Scapy, encapsulated in an Ethernet frame.
        """
        now = datetime.utcnow()
        port_stats = self.get_port_stats()
        payload = build_payload(is_switch=True, mac=self.host.MAC(), port_stats=port_stats, timestamp=now)
        payload_hex = payload.hex()
        iface = self.host.intfNames()[0]

        cmd = (
            'python3 -c "'
            "from scapy.all import Ether, UDP, Raw, sendp; "
            "payload=bytes.fromhex('{}'); "
            "pkt = Ether(src='{}', dst='{}')/UDP()/Raw(load=payload); "
            "sendp(pkt, iface='{}')"
            '"'
        ).format(payload_hex, self.host.MAC(), cc.MAC(), iface)
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
        self.addLink(s1h, s1)
        self.addLink(h1, s1)
        self.addLink(cc, s1)
        self.addLink(h2, s1)

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

    # Capture all packets excluding ICMP, MDNS, and ARP
    cc.cmd('tcpdump -i any -v -w all_packets.pcap not icmp6 and not port 5353 and not arp &')

    # Create an EnhancedSwitch instance (telemetry host + monitoring switch)
    enhanced_switch = EnhancedSwitch(s1h, s1, parameters={})
    
    # Send telemetry packets multiple times
    for _ in range(5):
        enhanced_switch.send_health_parameters(cc)
        time.sleep(5)
        cc.cmd('python filter_packets.py')


    # Generate some traffic between h1 and h2 (to produce non-zero counters)
    h2.cmd('iperf -s -u -i 1 > iperf_server_output &')
    time.sleep(1)
    h1.cmd('iperf -c ' + h2.IP() + ' -u -t 3 -b 10m')
    time.sleep(1)

    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    simpleTest()
