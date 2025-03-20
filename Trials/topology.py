#!/usr/bin/python
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import CPULimitedHost
from mininet.link import TCLink
import time

class SingleSwitchTopo(Topo):
    "Single switch connected to n hosts."
    def build(self, n=3):
        s1 = self.addSwitch('s1')
        s1h = self.addHost('s1h')
        h1 = self.addHost('h1')
        cc = self.addHost('cc')
        h2 = self.addHost('h2')
        self.addLink(s1h, s1)
        self.addLink(h1, s1)
        self.addLink(cc, s1)
        self.addLink(h2, s1)

def simpleTest():
    "Create and test a simple network"
    topo = SingleSwitchTopo(n=3)
    net = Mininet(topo=topo, link=TCLink)
    net.start()
    
    s1h = net.get('s1h')
    h1 = net.get('h1')
    cc = net.get('cc')
    h2 = net.get('h2')
    s1 = net.get('s1')

    cc.cmd('tcpdump -i any -w received_packets.pcap &')

    for _ in range(5):  
        s1h.cmd('python3 -c "from scapy.all import *; sendp(Ether(src=\'' + s1h.MAC() + '\', dst=\'' + cc.MAC() + '\')/Raw(load=\'Hello\'), iface=\'s1h-eth0\')"')
        time.sleep(1)

    h2.cmd('iperf -s -u -i 1 > iperf_server_output &')
    time.sleep(1)
    h1.cmd('iperf -c ' + h2.IP() + ' -u -t 3 -b 10m')
    time.sleep(1)

    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    simpleTest()
