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
from hlp_router import *

class CustomTopo(Topo):
    def build(self, n=3):
        s11 = self.addSwitch('s11', cls=HealthMonitoringSwitch)
        s11h = self.addHost('s11h')
        h11 = self.addHost('h11')
        cc1 = self.addHost('cc1')
        h12 = self.addHost('h12')
        h13 = self.addHost('h13')
        h14 = self.addHost('h14')
        h15 = self.addHost('h15')
        h16 = self.addHost('h16')
        h17 = self.addHost('h17')
        h18 = self.addHost('h18')
        s12 = self.addSwitch('s12', cls=HealthMonitoringSwitch)
        s12h = self.addHost('s12h')
        
        s21 = self.addSwitch('s21', cls=HealthMonitoringSwitch)
        s21h = self.addHost('s21h')
        h21 = self.addHost('h21')
        cc2 = self.addHost('cc2')
        h22 = self.addHost('h22')


        dc = self.addHost('dc')
        dcs = self.addSwitch('dcs1')
        self.addLink(dc, dcs)

        self.addLink(s11h, s11)
        self.addLink(h11, s11)
        self.addLink(cc1, s11)
        self.addLink(h12, s11)
        self.addLink(cc1, dcs)
        self.addLink(s11, dcs)
        self.addLink(s12h, s12)
        self.addLink(h13, s12)
        self.addLink(h14, s12)
        self.addLink(s12, dcs)
        self.addLink(s12, s11)
        self.addLink(h15, s12)
        self.addLink(h16, s12)
        self.addLink(h17, s11)
        self.addLink(h18, s11)

        self.addLink(s21h, s21)
        self.addLink(h21, s21)
        self.addLink(cc2, s21)
        self.addLink(h22, s21)
        self.addLink(cc2, dcs)
        self.addLink(s21, dcs)


def simpleTest():
    topo = CustomTopo(n=3)
    net = Mininet(topo=topo, link=TCLink, controller=None)
    net.addController('pox', controller=RemoteController, ip='127.0.0.1', port=6633)
    net.start()
    
    s11 = net.get('s11')
    s11.capture_initial_stats()
    s11h = net.get('s11h')
    h11 = net.get('h11')
    cc1 = net.get('cc1')
    h12 = net.get('h12')
    h13 = net.get('h13')
    h14 = net.get('h14')
    h15 = net.get('h15')
    h16 = net.get('h16')
    h17 = net.get('h17')
    h18 = net.get('h18')
    s12 = net.get('s12')
    s12h = net.get('s12h')
    s12.capture_initial_stats()

    s21 = net.get('s21')
    s21.capture_initial_stats()
    s21h = net.get('s21h')
    h21 = net.get('h21')
    cc2 = net.get('cc2')
    h22 = net.get('h22')

    dc = net.get('dc')

    # net.pingAll()

    # Print IP Addressses
    print("IP Addresses:")
    print("h11: ", h11.IP())
    print("h12: ", h12.IP())
    print("cc1: ", cc1.IP())
    print("dc: ", dc.IP())
    print("s11: ", s11.IP())
    print("s11h: ", s11h.IP())
    print("h13: ", h13.IP())
    print("h14: ", h14.IP())
    print("h15: ", h15.IP())
    print("h16: ", h16.IP())
    print("h17: ", h17.IP())
    print("h18: ", h18.IP())
    print("s12: ", s12.IP())
    print("s12h: ", s12h.IP())

    print("IP Addresses:")
    print("h11: ", h21.IP())
    print("h12: ", h22.IP())
    print("cc1: ", cc2.IP())
    print("dc: ", dc.IP())
    print("s11: ", s21.IP())
    print("s11h: ", s21h.IP())

        

    h12.cmd('iperf -s -u -i 1 > iperf_server_output &')
    time.sleep(1)
    h11.cmd('iperf -c ' + h12.IP() + ' -u -b 0.1k &')
    time.sleep(1)
    h13.cmd('iperf -c ' + h12.IP() + ' -u -b 0.1k &')
    time.sleep(1)
    h14.cmd('iperf -c ' + h12.IP() + ' -u -b 0.1k &')
    time.sleep(1)
    h15.cmd('iperf -c ' + h12.IP() + ' -u -b 0.1k &')
    time.sleep(1)
    h16.cmd('iperf -c ' + h12.IP() + ' -u -b 0.1k &')
    time.sleep(1)
    h17.cmd('iperf -c ' + h12.IP() + ' -u -b 0.1k &')
    time.sleep(1)
    h18.cmd('iperf -c ' + h12.IP() + ' -u -b 0.1k &')
    time.sleep(1)

    h22.cmd('iperf -s -u -i 1 > iperf_server_output &')
    time.sleep(1)
    h21.cmd('iperf -c ' + h22.IP() + ' -u -b 0.1k &')
    time.sleep(1)

    enhanced_switch11 = EnhancedSwitch(s11h, s11, parameters={})
    enhanced_switch12 = EnhancedSwitch(s12h, s12, parameters={})
    enhanced_switch21 = EnhancedSwitch(s21h, s21, parameters={})

    dc.cmd('tcpdump -i any udp port 12345 -w capture.pcap &')
    cc1.cmd('tcpdump -i any -v -w cc1.pcap not icmp6 and not port 5353 and not arp &')
    cc2.cmd('tcpdump -i any -v -w cc2.pcap not icmp6 and not port 5353 and not arp &')
    time.sleep(5)
    print("Starting telemetry...")

    ticks = 0    
    while True:
        time.sleep(1)
        try:
            ticks += 1
            ticks %= 10
            if ticks%2 == 0:
                # End tcpdump of cc
                cc1.cmd('kill %tcpdump')
                cc2.cmd('kill %tcpdump')
                # Read the file cc1.pcap and send a "Hello" message to the dc from cc
                cc1.cmd('python3 packet_processor.py cc1.pcap cc1')
                cc2.cmd('python3 packet_processor.py cc2.pcap cc2')
                # Send the data to the dc
                cc1.cmd('cat cc1_payload.txt | nc -u -w 1 {} 12345'.format(dc.IP())) # send data as UDP
                time.sleep(0.1)
                cc2.cmd('cat cc2_payload.txt | nc -u -w 1 {} 12345'.format(dc.IP()))
                print(f"cc1: Sent UDP packet at {time.time()}")
                print(f"cc2: Sent UDP packet at {time.time()}")
                # Delete the file
                cc1.cmd('rm cc1.pcap')
                cc2.cmd('rm cc2.pcap')
                # Restart tcpdump
                cc1.cmd('tcpdump -i any -v -w cc1.pcap not icmp6 and not port 5353 and not arp &')
                cc2.cmd('tcpdump -i any -v -w cc2.pcap not icmp6 and not port 5353 and not arp &')
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

            enhanced_switch11.send_health_parameters(cc1)
            enhanced_switch12.send_health_parameters(cc1)
            enhanced_switch21.send_health_parameters(cc2)
        except KeyboardInterrupt:
            print("Stopping telemetry...")
            break


    cc1.cmd('killall tcpdump')
    cc1.cmd('python3 packet_processor.py cc1.pcap cc1')
    cc2.cmd('killall tcpdump')
    cc2.cmd('python3 packet_processor.py cc2.pcap cc2')


    h12.cmd('killall iperf')
    h22.cmd('killall iperf')


    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    simpleTest()
