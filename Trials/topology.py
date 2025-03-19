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
    
    # Get the host objects
    h1 = net.get('h1')
    h3 = net.get('h3')
    
    # Run a script on h1 to send UDP packets to h3
    h1.cmd('python send_udp.py %s &' % h3.IP())
    
    # Run a script on h3 to receive UDP packets
    h3.cmd('python receive_udp.py &')

    # Wait for the scripts to finish
    time.sleep(10)
        
    # Stop the network
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    simpleTest()
