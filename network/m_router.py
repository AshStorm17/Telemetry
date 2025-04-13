from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost, Host, RemoteController
from mininet.link import TCLink
from mininet.log import setLogLevel, info
import time
import datetime
from scapy.all import Ether, UDP, Raw, sendp
import socket

# Import health monitoring classes for switch and router
from health_switch import HealthMonitoringSwitch
from health_router import HealthMonitoringRouter

# Import EnhancedSwitch telemetry from hlp_switch and EnhancedRouter telemetry from hlp_router.
from hlp_switch import EnhancedSwitch
from hlp_router import EnhancedRouter

class CustomTopo(Topo):
    def build(self):
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2', cls=HealthMonitoringSwitch)
        r1 = self.addHost('r1', cls=HealthMonitoringRouter)
        s2h = self.addHost('s2h')
        cc1 = self.addHost('cc1')
        ccs1 = self.addSwitch('ccs1')
        cc2 = self.addHost('cc2')
        dcs1 = self.addSwitch('dcs1')
        dcs2 = self.addSwitch('dcs2')
        dc = self.addHost('dc')

        self.addLink(h1, s1)
        self.addLink(h2, s2)
        self.addLink(h3, s2)
        self.addLink(h4, s2)
        self.addLink(s2h, s2)
        self.addLink(s1, r1)
        self.addLink(s2, r1)
        self.addLink(ccs1, r1)
        self.addLink(ccs1, cc1)
        self.addLink(cc2, s2)
        self.addLink(cc1, dcs1)
        self.addLink(cc2, dcs2)
        self.addLink(dc, dcs1)
        self.addLink(dc, dcs2)


def simpleTest():
    topo = CustomTopo()
    net = Mininet(topo=topo, link=TCLink, controller=None)
    net.addController('pox', controller=RemoteController, ip='127.0.0.1', port=6633)
    net.start()
    
    # Retrieve nodes from the topology
    r1 = net.get('r1')
    r1.cmd('sysctl -w net.ipv4.ip_forward=1')
    s1 = net.get('s1')
    s2 = net.get('s2')
    s2.capture_initial_stats()
    s2h = net.get('s2h')
    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')
    h4 = net.get('h4')
    cc1 = net.get('cc1')
    cc2 = net.get('cc2')
    dc = net.get('dc')
    r1.capture_initial_stats()

    # Basic connectivity
    net.pingAll()
    
    print("IP Addresses:")
    print("h1: ", h1.IP())
    print("h2: ", h2.IP())
    print("h3: ", h3.IP())
    print("h4: ", h4.IP())
    print("cc1: ", cc1.IP())
    print("cc2: ", cc2.IP())
    print("dc: ", dc.IP())
    print("s2: ", s2.IP())
    print("s2h: ", s2h.IP())
    print("r1: ", r1.IP())
        
    # Set up iperf server on h2 and h4 and start a UDP iperf client on h1 and h3
    h4.cmd('iperf -s -u -i 1 > iperf_server_output &')
    time.sleep(1)
    h3.cmd('iperf -c ' + h4.IP() + ' -u -b 10m &')
    time.sleep(1)
    h2.cmd('iperf -s -u -i 1 > iperf_server_output &')
    time.sleep(1)
    h1.cmd('iperf -c ' + h2.IP() + ' -u -b 10m &')
    time.sleep(1)
    
    # Create telemetry objects for switch and router.
    enhanced_switch = EnhancedSwitch(s2h, s2, parameters={})
    enhanced_router = EnhancedRouter(r1, parameters={})
    
    # Start tcpdump on the data center and cluster center hosts.
    dc.cmd('tcpdump -i any udp port 12345 -w capture.pcap &')
    cc1.cmd('tcpdump -i any -v -w cc1.pcap not icmp6 and not port 5353 and not arp &')
    cc2.cmd('tcpdump -i any -v -w cc2.pcap not icmp6 and not port 5353 and not arp &')

    ticks = 0    
    while True:
        time.sleep(1)
        try:
            ticks += 1
            ticks %= 10
            if ticks % 2 == 0:
                # Process tcpdump at the cluster center:
                cc1.cmd('kill %tcpdump')
                cc2.cmd('kill %tcpdump')
                # Process the captured file and send data from cc to dc
                cc1.cmd('python3 packet_processor.py cc1.pcap cc1')
                cc1.cmd('cat cc1_payload.txt | nc -u -w 1 {} 12345'.format(dc.IP()))
                print(f"cc1: Sent UDP packet at {time.time()}")
                cc1.cmd('rm cc1.pcap')
                cc1.cmd('tcpdump -i any -v -w cc1.pcap not icmp6 and not port 5353 and not arp &')
                cc2.cmd('python3 packet_processor.py cc2.pcap cc2')
                cc2.cmd('cat cc2_payload.txt | nc -u -w 1 {} 12345'.format(dc.IP()))
                print(f"cc2: Sent UDP packet at {time.time()}")
                cc2.cmd('rm cc2.pcap')
                cc2.cmd('tcpdump -i any -v -w cc2.pcap not icmp6 and not port 5353 and not arp &')
            if ticks == 9:
                # Process tcpdump at the data center:
                dc.cmd('kill %tcpdump')
                dc.cmd('python3 dc_packet_saver.py capture.pcap')
                print("PROCESSING at dc")
                dc.cmd('rm capture.pcap')
                dc.cmd('tcpdump -i any udp port 12345 -w capture.pcap &')

            # Send telemetry data from both the switch and the router.
            enhanced_switch.send_health_parameters(cc2)
            enhanced_router.send_health_parameters(cc1)
        except KeyboardInterrupt:
            print("Stopping telemetry...")
            break

    cc1.cmd('killall tcpdump')
    cc1.cmd('python3 packet_processor.py cc1.pcap cc1')
    cc2.cmd('killall tcpdump')
    cc2.cmd('python3 packet_processor.py cc2.pcap cc2')
    h2.cmd('killall iperf')
    h4.cmd('killall iperf')

    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    simpleTest()
