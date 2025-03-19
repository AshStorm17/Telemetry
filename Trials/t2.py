#!/usr/bin/env python

from mininet.net import Mininet
from mininet.node import Controller
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from scapy.all import *
import time
import subprocess

def udp_test():
    "Create a simple network and send UDP packets."

    net = Mininet(topo=None, build=False, ipBase='10.0.0.0/8')
    info('*** Adding controller\n')
    net.addController(name='c0')

    info('*** Adding hosts\n')
    h1 = net.addHost('h1', ip='10.0.0.1')
    h2 = net.addHost('h2', ip='10.0.0.2')
    h3 = net.addHost('h3', ip='10.0.0.3')

    info('*** Adding switch\n')
    s1 = net.addSwitch('s1')


    info('*** Creating links\n')
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)

    info('*** Starting network\n')
    net.start()

    info('*** Starting receiver on h3\n')
    h3.cmd('tcpdump -i h3-eth0 udp port 5000 -w h3_capture.pcap &')

    h1.cmd('ifconfig h1-eth3 up')

    info('*** Sending UDP packets from s1 to h3\n')
    while True:
        packet = IP(dst='10.0.0.3')/UDP(dport=5000)/Raw(load='Hello')
        send(packet, iface='h1-eth3')
        time.sleep(1)
        info('*** Stopping receiver on h3 and extracting payload\n')
        h3.cmd('pkill tcpdump')
        h3.cmd("tshark -r h3_capture.pcap -T fields -e udp.payload_raw > payload.txt") #Modified tshark command
        result = h3.cmd('cat payload.txt')
        print("Payloads received on h3:")
        print(result)

    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    udp_test()
