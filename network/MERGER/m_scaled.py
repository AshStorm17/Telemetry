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
from hlp import *

class CustomTopo(Topo):
    def build(self, n=3):
        
        # DC
        dc = self.addHost('dc')
        dcs = self.addSwitch('dcs1')

        # Cluster 1
        s11 = self.addSwitch('s11', cls=HealthMonitoringSwitch)
        s11h = self.addHost('s11h')
        s12 = self.addSwitch('s12', cls=HealthMonitoringSwitch)
        s12h = self.addHost('s12h')
        h11 = self.addHost('h11')
        h12 = self.addHost('h12')
        h13 = self.addHost('h13')
        h14 = self.addHost('h14')
        cc1 = self.addHost('cc1')
        self.addLink(s11h, s11)
        self.addLink(s12h, s12)
        self.addLink(s11, s12)
        self.addLink(h11, s11)
        self.addLink(h12, s11)
        self.addLink(h13, s12)
        self.addLink(h14, s12)
        self.addLink(cc1, s11)
        self.addLink(cc1, s12)
        self.addLink(s11, dcs)
        self.addLink(s12, dcs)
        self.addLink(cc1, dcs)
        self.addLink(dc, dcs)

        # Cluster 2
        s21 = self.addSwitch('s21', cls=HealthMonitoringSwitch)
        s21h = self.addHost('s21h')
        s22 = self.addSwitch('s22', cls=HealthMonitoringSwitch)
        s22h = self.addHost('s22h')
        h21 = self.addHost('h21')
        h22 = self.addHost('h22')
        h23 = self.addHost('h23')
        h24 = self.addHost('h24')
        cc2 = self.addHost('cc2')
        self.addLink(s21h, s21)
        self.addLink(s22h, s22)
        self.addLink(s21, s22)
        self.addLink(h21, s21)
        self.addLink(h22, s21)
        self.addLink(h23, s22)
        self.addLink(h24, s22)
        self.addLink(cc2, s21)
        self.addLink(cc2, s22)
        self.addLink(s21, dcs)
        self.addLink(s22, dcs)
        self.addLink(cc2, dcs)

        # Cluster 3
        s31 = self.addSwitch('s31', cls=HealthMonitoringSwitch)
        s31h = self.addHost('s31h')
        s32 = self.addSwitch('s32', cls=HealthMonitoringSwitch)
        s32h = self.addHost('s32h')
        h31 = self.addHost('h31')
        h32 = self.addHost('h32')
        h33 = self.addHost('h33')
        h34 = self.addHost('h34')
        cc3 = self.addHost('cc3')
        self.addLink(s31h, s31)
        self.addLink(s32h, s32)
        self.addLink(s31, s32)
        self.addLink(h31, s31)
        self.addLink(h32, s31)
        self.addLink(h33, s32)
        self.addLink(h34, s32)
        self.addLink(cc3, s31)
        self.addLink(cc3, s32)
        self.addLink(s31, dcs)
        self.addLink(s32, dcs)
        self.addLink(cc3, dcs)



def simpleTest():
    topo = CustomTopo(n=3)
    net = Mininet(topo=topo, link=TCLink, controller=None)
    net.addController('pox', controller=RemoteController, ip='127.0.0.1', port=6633)
    net.start()
    
    s11 = net.get('s11')
    s11h = net.get('s11h')
    s12 = net.get('s12')
    s12h = net.get('s12h')
    h11 = net.get('h11')
    h12 = net.get('h12')
    h13 = net.get('h13')
    h14 = net.get('h14')
    cc1 = net.get('cc1')
    s21 = net.get('s21')
    s21h = net.get('s21h')
    s22 = net.get('s22')
    s22h = net.get('s22h')
    h21 = net.get('h21')
    h22 = net.get('h22')
    h23 = net.get('h23')
    h24 = net.get('h24')
    cc2 = net.get('cc2')
    s31 = net.get('s31')
    s31h = net.get('s31h')
    s32 = net.get('s32')
    s32h = net.get('s32h')
    h31 = net.get('h31')
    h32 = net.get('h32')
    h33 = net.get('h33')
    h34 = net.get('h34')
    cc3 = net.get('cc3')
    dc = net.get('dc')


    # net.pingAll()

    h12.cmd('iperf -s -u -i 1 > iperf_server_output &')
    time.sleep(1)
    h14.cmd('iperf -c ' + h12.IP() + ' -u -b 1m &')
    h13.cmd('iperf -s -u -i 1 > iperf_server_output &')
    time.sleep(1)
    h11.cmd('iperf -c ' + h13.IP() + ' -u -b 1m &')

    h22.cmd('iperf -s -u -i 1 > iperf_server_output &')
    time.sleep(1)
    h24.cmd('iperf -c ' + h22.IP() + ' -u -b 1m &')
    h23.cmd('iperf -s -u -i 1 > iperf_server_output &')
    time.sleep(1)
    h21.cmd('iperf -c ' + h23.IP() + ' -u -b 1m &')

    h32.cmd('iperf -s -u -i 1 > iperf_server_output &')
    time.sleep(1)
    h34.cmd('iperf -c ' + h32.IP() + ' -u -b 1m &')
    h33.cmd('iperf -s -u -i 1 > iperf_server_output &')
    time.sleep(1)
    h31.cmd('iperf -c ' + h33.IP() + ' -u -b 1m &')


    enhanced_switch_s11 = EnhancedSwitch(s11h, s11, parameters={})
    enhanced_switch_s12 = EnhancedSwitch(s12h, s12, parameters={})
    enhanced_switch_s21 = EnhancedSwitch(s21h, s21, parameters={})
    enhanced_switch_s22 = EnhancedSwitch(s22h, s22, parameters={})
    enhanced_switch_s31 = EnhancedSwitch(s31h, s31, parameters={})
    enhanced_switch_s32 = EnhancedSwitch(s32h, s32, parameters={})

    dc.cmd('tcpdump -i any udp port 12345 -w capture.pcap &')
    cc1.cmd('tcpdump -i any -v -w cc1.pcap not icmp6 and not port 5353 and not arp &')
    cc2.cmd('tcpdump -i any -v -w cc2.pcap not icmp6 and not port 5353 and not arp &')
    cc3.cmd('tcpdump -i any -v -w cc3.pcap not icmp6 and not port 5353 and not arp &')

    ticks = 0    
    while True:
        time.sleep(1)
        try:
            ticks += 1
            ticks %= 10
            if ticks%5 == 0:
                # End tcpdump of cc
                cc1.cmd('kill %tcpdump')
                cc2.cmd('kill %tcpdump')
                cc3.cmd('kill %tcpdump')
                # Read the file cc1.pcap and send a "Hello" message to the dc from cc
                cc1.cmd('python3 packet_processor.py cc1.pcap cc1')
                cc2.cmd('python3 packet_processor.py cc2.pcap cc2')
                cc3.cmd('python3 packet_processor.py cc3.pcap cc3')
                # Send the data to the dc
                cc1.cmd('cat cc1_payload.txt | nc -u -w 1 {} 12345'.format(dc.IP())) # send data as UDP
                cc2.cmd('cat cc2_payload.txt | nc -u -w 1 {} 12345'.format(dc.IP()))
                cc3.cmd('cat cc3_payload.txt | nc -u -w 1 {} 12345'.format(dc.IP()))
                print(f"cc1: Sent UDP packet at {time.time()}")
                print(f"cc2: Sent UDP packet at {time.time()}")
                print(f"cc3: Sent UDP packet at {time.time()}")
                # Delete the file
                cc1.cmd('rm cc1.pcap')
                cc2.cmd('rm cc2.pcap')
                cc3.cmd('rm cc3.pcap')
                # Restart tcpdump
                cc1.cmd('tcpdump -i any -v -w cc1.pcap not icmp6 and not port 5353 and not arp &')
                cc2.cmd('tcpdump -i any -v -w cc2.pcap not icmp6 and not port 5353 and not arp &')
                cc3.cmd('tcpdump -i any -v -w cc3.pcap not icmp6 and not port 5353 and not arp &')
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

            enhanced_switch_s11.send_health_parameters(cc1)
            enhanced_switch_s12.send_health_parameters(cc1)
            enhanced_switch_s21.send_health_parameters(cc2)
            enhanced_switch_s22.send_health_parameters(cc2)
            enhanced_switch_s31.send_health_parameters(cc3)
            enhanced_switch_s32.send_health_parameters(cc3)
        except KeyboardInterrupt:
            print("Stopping telemetry...")
            break


    cc1.cmd('killall tcpdump')
    cc2.cmd('killall tcpdump')
    cc3.cmd('killall tcpdump')
    dc.cmd('killall tcpdump')
    cc1.cmd('python3 packet_processor.py cc1.pcap cc1')
    cc2.cmd('python3 packet_processor.py cc2.pcap cc2')
    cc3.cmd('python3 packet_processor.py cc3.pcap cc3')

    h12.cmd('killall iperf')
    h14.cmd('killall iperf')
    h11.cmd('killall iperf')
    h13.cmd('killall iperf')
    h22.cmd('killall iperf')
    h24.cmd('killall iperf')
    h21.cmd('killall iperf')
    h23.cmd('killall iperf')
    h32.cmd('killall iperf')
    h34.cmd('killall iperf')
    h31.cmd('killall iperf')
    h33.cmd('killall iperf')


    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    simpleTest()