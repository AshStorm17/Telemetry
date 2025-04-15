from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost, Host
from mininet.link import TCLink
from mininet.log import setLogLevel, info
# Add remote controller
from mininet.node import RemoteController
import time
import datetime
from scapy.all import Ether, UDP, Raw, sendp
import socket
from health_switch import HealthMonitoringSwitch
from packet_processor import end2end_cc2dc
from hlp_switch import *
import os

class CustomTopo(Topo):
    def build(self, n=3):
        s1 = self.addSwitch('s1', cls=HealthMonitoringSwitch)
        s1h = self.addHost('s1h')
        dcs = self.addSwitch('dcs1')
        h1 = self.addHost('h1')
        cc = self.addHost('cc')
        h2 = self.addHost('h2')
        dc = self.addHost('dc')
        self.addLink(s1h, s1)
        self.addLink(h1, s1)
        self.addLink(cc, s1)
        self.addLink(h2, s1)
        self.addLink(dc, dcs)
        self.addLink(cc, dcs)
        self.addLink(s1, dcs)


def simpleTest():
    topo = CustomTopo(n=3)
    net = Mininet(topo=topo, link=TCLink, controller=None)
    net.addController('pox', controller=RemoteController, ip='127.0.0.1', port=6633)
    net.start()
    
    s1 = net.get('s1')
    s1.capture_initial_stats()
    s1h = net.get('s1h')
    h1 = net.get('h1')
    cc = net.get('cc')
    h2 = net.get('h2')
    dc = net.get('dc')

    net.pingAll()

    # Print IP Addressses
    print("IP Addresses:")
    print("h1: ", h1.IP())
    print("h2: ", h2.IP())
    print("cc: ", cc.IP())
    print("dc: ", dc.IP())
    print("s1: ", s1.IP())
    print("s1h: ", s1h.IP())


    cc.cmd(f'python3 init_last_seen.py cc1 {"46:eb:19:fd:51:d9"}')

    cc.cmd('touch cc1_tcp_payload.txt')
    cc.cmd('mkdir cc1_tcp_payload')

    h2.cmd('iperf -s -u -i 1 > iperf_server_output &')
    time.sleep(1)
    h1.cmd('iperf -c ' + h2.IP() + ' -u -b 10m &')
    time.sleep(1)
    enhanced_switch = EnhancedSwitch(s1h, s1, parameters={})
    dc.cmd('tcpdump -i any udp port 12345 -w capture.pcap &')
    cc.cmd('tcpdump -i any -v -w cc1.pcap not icmp6 and not port 5353 and not arp &')

    ticks = 0    
    while True:
        time.sleep(1)
        try:
            ticks += 1
            ticks %= 10
            if ticks%2 == 0:
                # End tcpdump of cc
                cc.cmd('kill %tcpdump')
                # Read the file cc1.pcap and send a "Hello" message to the dc from cc
                cc.cmd('python3 packet_processor.py cc1.pcap cc1')
                # Send the data to the dc
                cc.cmd('cat cc1_payload.txt | nc -u -w 1 {} 12345'.format(dc.IP())) # send data as UDP
                
                cc.cmd('python3 check_last_seen.py cc1.pcap cc1')
                cc.cmd('python3 send_sos_packets.py cc1')
                for sos_packet in os.listdir("cc1_tcp_payload/"):
                    print(f"cc1: Sending SOS TCP packet {sos_packet} to dc")
                    cc.cmd(f'cat cc1_tcp_payload/{sos_packet}.txt | nc -u -w 1 {dc.IP()} 23456')
                cc.cmd(f'sudo rm -r cc1_tcp_payload')
                cc.cmd(f'sudo rm cc1_tcp_payload.txt')
                cc.cmd(f'sudo touch cc1_tcp_payload.txt')
                cc.cmd(f'sudo mkdir cc1_tcp_payload')

                print(f"cc1: Sent UDP packet at {time.time()}")
                # Delete the file
                cc.cmd('rm cc1.pcap')
                cc.cmd('rm cc1_tcp_payload/*')
                # Restart tcpdump
                cc.cmd('tcpdump -i any -v -w cc1.pcap not icmp6 and not port 5353 and not arp &')
            if ticks == 9:
                # End tcpdump of dc
                dc.cmd('kill %tcpdump')
                # Read the file capture.pcap and send a "Hello" message to the cc from dc
                dc.cmd('python3 dc_packet_saver.py capture.pcap')
                # print PROCESSING
                print("PROCESSING at dc")
                # delete the file
                dc.cmd('rm capture.pcap')
                # Begin the tcpdump of dc
                dc.cmd('tcpdump -i any udp port 12345 -w capture.pcap &')

            enhanced_switch.send_health_parameters(cc)
        except KeyboardInterrupt:
            print("Stopping telemetry...")
            break


    cc.cmd('killall tcpdump')
    cc.cmd('python3 packet_processor.py cc1.pcap cc1')

    cc.cmd('rm -rf cc1_tcp_payload/')
    cc.cmd('rm cc1_tcp_payload.txt')

    h2.cmd('killall iperf')

    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    simpleTest()