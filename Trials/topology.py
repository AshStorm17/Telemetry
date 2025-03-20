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
        switch = self.addSwitch('s1')
        for h in range(n):
            host = self.addHost('h%s' % (h + 1), cpu=.6/n)
            self.addLink(host, switch, bw=500, delay='10ms', loss=0, max_queue_size=100, use_htb=True)

def simpleTest():
    "Create and test a simple network"
    topo = SingleSwitchTopo(n=3)
    net = Mininet(topo=topo, link=TCLink)
    net.start()
    
    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')
    s1 = net.get('s1')

    # Set MAC address for h1's interface to simulate s1's MAC
    h1.setMAC('00:00:00:00:00:01', intf='h1-eth0')

    # Start a listener on h3 to receive packets
    h3.cmd('tcpdump -i any -w received_packets.pcap &')

    # Send packets from h1 (simulating s1) to h3 with h1's MAC address
    for _ in range(5):  
        h1.cmd('python3 -c "from scapy.all import *; sendp(Ether(src=\'00:00:00:00:00:01\', dst=\'' + h3.MAC() + '\')/Raw(load=\'Hello\'), iface=\'h1-eth0\')"')
        time.sleep(1)

    # Running iperf test as before
    h1.cmd('iperf -s -u -i 1 > iperf_server_output &')
    time.sleep(1)
    h2.cmd('iperf -c ' + h1.IP() + ' -u -t 3 -b 10m')
    time.sleep(1)

    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    simpleTest()
