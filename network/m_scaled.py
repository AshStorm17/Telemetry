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
from health_router import HealthMonitoringRouter


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
        h23 = self.addHost('h23')
        h24 = self.addHost('h24')
        h25 = self.addHost('h25')
        h26 = self.addHost('h26')
        h27 = self.addHost('h27')
        h28 = self.addHost('h28')
        s22 = self.addSwitch('s22', cls=HealthMonitoringSwitch)
        s22h = self.addHost('s22h')

        h31 = self.addHost('h31')
        h32 = self.addHost('h32')
        h33 = self.addHost('h33')
        h34 = self.addHost('h34')
        h35 = self.addHost('h35')
        h36 = self.addHost('h36')
        h37 = self.addHost('h37')
        h38 = self.addHost('h38')
        s31 = self.addSwitch('s31', cls=HealthMonitoringSwitch)
        s31h = self.addHost('s31h')
        s32 = self.addSwitch('s32', cls=HealthMonitoringSwitch)
        s32h = self.addHost('s32h')
        cc3 = self.addHost('cc3')

        r1 = self.addHost('r1', cls=HealthMonitoringRouter)
        r2 = self.addHost('r2', cls=HealthMonitoringRouter)
        r3 = self.addHost('r3', cls=HealthMonitoringRouter)


        dc = self.addHost('dc')
        dcs = self.addSwitch('dcs1')
        self.addLink(dc, dcs)

        # cluster-1
        self.addLink(s11h, s11)
        self.addLink(h11, s11)
        self.addLink(h12,s11)
        self.addLink(h13, s11)
        self.addLink(h14, s11)
        self.addLink(cc1, s11)

        self.addLink(h15, s12)
        self.addLink(h16, s12)
        self.addLink(h17, s12)
        self.addLink(h18, s12)
        self.addLink(s12, s11)
        self.addLink(s12h, s12)
        self.addLink(cc1, s12)

        self.addLink(cc1, dcs)
        self.addLink(s11, dcs)
        self.addLink(s12, dcs)


        # cluster-2
        self.addLink(s21h, s21)
        self.addLink(h21, s21)
        self.addLink(h22,s21)
        self.addLink(h23, s21)
        self.addLink(h24, s21)
        self.addLink(cc2, s21)

        self.addLink(h25, s22)
        self.addLink(h26, s22)
        self.addLink(h27, s22)
        self.addLink(h28, s22)
        self.addLink(s22, s21)
        self.addLink(s22h, s22)
        self.addLink(cc2, s22)

        self.addLink(cc2, dcs)
        self.addLink(s21, dcs)
        self.addLink(s22, dcs)

        # cluster-3
        self.addLink(s31h, s31)
        self.addLink(h31, s31)
        self.addLink(h32, s31)
        self.addLink(h33, s31)
        self.addLink(h34, s31)
        self.addLink(cc3, s31)

        self.addLink(h35, s32)
        self.addLink(h36, s32)
        self.addLink(h37, s32)
        self.addLink(h38, s32)
        self.addLink(s32, s31)
        self.addLink(s32h, s32)
        self.addLink(cc3, s32)

        self.addLink(cc3, dcs)
        self.addLink(s31, dcs)
        self.addLink(s32, dcs)

        # adding links for routers

        self.addLink(r1, s12)
        self.addLink(s21, r1)

        self.addLink(r2, s22)
        self.addLink(s31, r2)

        self.addLink(r3, s32)
        self.addLink(s11, r3)





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
    s12.capture_initial_stats()
    s12h = net.get('s12h')

    s21 = net.get('s21')
    s21.capture_initial_stats()
    s21h = net.get('s21h')
    h21 = net.get('h21')
    cc2 = net.get('cc2')
    h22 = net.get('h22')
    h23 = net.get('h23')
    h24 = net.get('h24')
    h25 = net.get('h25')
    h26 = net.get('h26')
    h27 = net.get('h27')
    h28 = net.get('h28')
    s22 = net.get('s12')
    s22.capture_initial_stats()
    s22h = net.get('s22h')

    s31 = net.get('s31')
    s31.capture_initial_stats()
    s31h = net.get('s31h')
    h31 = net.get('h31')
    cc3 = net.get('cc3')
    h32 = net.get('h32')
    h33 = net.get('h33')
    h34 = net.get('h34')
    h35 = net.get('h35')
    h36 = net.get('h36')
    h37 = net.get('h37')
    h38 = net.get('h38')
    s32 = net.get('s32')
    s32.capture_initial_stats()
    s32h = net.get('s32h')

    r1 = net.get('r1')
    r1.cmd('sysctl -w net.ipv4.ip_forward=1')
    r1.capture_initial_stats()

    r2 = net.get('r2')
    r2.cmd('sysctl -w net.ipv4.ip_forward=1')
    r2.capture_initial_stats()

    r3 = net.get('r3')
    r3.cmd('sysctl -w net.ipv4.ip_forward=1')
    r3.capture_initial_stats()

    dc = net.get('dc')


    # net.pingAll()

    # # Print IP Addressses
    # print("IP Addresses:")
    # print("h11: ", h11.IP())
    # print("h12: ", h12.IP())
    # print("cc1: ", cc1.IP())
    # print("dc: ", dc.IP())
    # print("s11: ", s11.IP())
    # print("s11h: ", s11h.IP())
    # print("h13: ", h13.IP())
    # print("h14: ", h14.IP())
    # print("h15: ", h15.IP())
    # print("h16: ", h16.IP())
    # print("h17: ", h17.IP())
    # print("h18: ", h18.IP())
    # print("s12: ", s12.IP())
    # print("s12h: ", s12h.IP())

    # print("IP Addresses:")
    # print("h11: ", h21.IP())
    # print("h12: ", h22.IP())
    # print("cc1: ", cc2.IP())
    # print("dc: ", dc.IP())
    # print("s11: ", s21.IP())
    # print("s11h: ", s21h.IP())

        

    h12.cmd('iperf -s -u -i 1 > iperf_server_output &')
    time.sleep(1)
    h11.cmd('iperf -c ' + h12.IP() + ' -u -b 1k &')
    time.sleep(1)
    h13.cmd('iperf -c ' + h12.IP() + ' -u -b 1k &')
    time.sleep(1)
    h14.cmd('iperf -c ' + h12.IP() + ' -u -b 1k &')
    time.sleep(1)
    h15.cmd('iperf -c ' + h12.IP() + ' -u -b 1k &')
    time.sleep(1)
    h16.cmd('iperf -c ' + h12.IP() + ' -u -b 1k &')
    time.sleep(1)
    h17.cmd('iperf -c ' + h12.IP() + ' -u -b 1k &')
    time.sleep(1)
    h18.cmd('iperf -c ' + h12.IP() + ' -u -b 1k &')
    time.sleep(1)

    h22.cmd('iperf -s -u -i 1 > iperf_server_output &')
    time.sleep(1)
    h21.cmd('iperf -c ' + h22.IP() + ' -u -b 1k &')
    time.sleep(1)
    h23.cmd('iperf -c ' + h22.IP() + ' -u -b 1k &')
    time.sleep(1)
    h24.cmd('iperf -c ' + h22.IP() + ' -u -b 1k &')
    time.sleep(1)
    h25.cmd('iperf -c ' + h22.IP() + ' -u -b 1k &')
    time.sleep(1)
    h26.cmd('iperf -c ' + h22.IP() + ' -u -b 1k &')
    time.sleep(1)
    h27.cmd('iperf -c ' + h22.IP() + ' -u -b 1k &')
    time.sleep(1)
    h28.cmd('iperf -c ' + h22.IP() + ' -u -b 1k &')
    time.sleep(1)

    h32.cmd('iperf -s -u -i 1 > iperf_server_output &')
    time.sleep(1)
    h31.cmd('iperf -c ' + h32.IP() + ' -u -b 1k &')
    time.sleep(1)
    h33.cmd('iperf -c ' + h32.IP() + ' -u -b 1k &')
    time.sleep(1)
    h34.cmd('iperf -c ' + h32.IP() + ' -u -b 1k &')
    time.sleep(1)
    h35.cmd('iperf -c ' + h32.IP() + ' -u -b 1k &')
    time.sleep(1)
    h36.cmd('iperf -c ' + h32.IP() + ' -u -b 1k &')
    time.sleep(1)
    h37.cmd('iperf -c ' + h32.IP() + ' -u -b 1k &')
    time.sleep(1)
    h38.cmd('iperf -c ' + h32.IP() + ' -u -b 1k &')
    time.sleep(1)



    enhanced_switch11 = EnhancedSwitch(s11h, s11, parameters={})
    enhanced_switch12 = EnhancedSwitch(s12h, s12, parameters={})
    enhanced_switch21 = EnhancedSwitch(s21h, s21, parameters={})
    enhanced_switch22 = EnhancedSwitch(s22h, s22, parameters={})
    enhanced_switch31 = EnhancedSwitch(s31h, s31, parameters={})
    enhanced_switch32 = EnhancedSwitch(s32h, s32, parameters={})

    enhanced_router1 = EnhancedRouter(r1, parameters={})
    enhanced_router2 = EnhancedRouter(r2, parameters={})
    enhanced_router3 = EnhancedRouter(r3, parameters={})
    enhanced_router1.start()
    enhanced_router2.start()
    enhanced_router3.start()

    dc.cmd('tcpdump -i any udp port 12345 -w capture.pcap &')
    cc1.cmd('tcpdump -i any -v -w cc1.pcap not icmp6 and not port 5353 and not arp &')
    cc2.cmd('tcpdump -i any -v -w cc2.pcap not icmp6 and not port 5353 and not arp &')
    cc3.cmd('tcpdump -i any -v -w cc3.pcap not icmp6 and not port 5353 and not arp &')
    time.sleep(10)
    print("Starting Telemetry...")

    ticks = 0    
    while True:
        time.sleep(0.5)
        try:
            ticks += 1
            ticks %= 10
            if ticks%2 == 0:
                # End tcpdump of cc
                cc1.cmd('kill %tcpdump')
                cc2.cmd('kill %tcpdump')
                cc3.cmd('kill %tcpdump')
                # Read the file cc1.pcap and send message to the dc from cc
                cc1.cmd('python3 packet_processor.py cc1.pcap cc1')
                time.sleep(1)
                cc2.cmd('python3 packet_processor.py cc2.pcap cc2')
                time.sleep(1)
                cc3.cmd('python3 packet_processor.py cc3.pcap cc3')
                time.sleep(1)
                # Send the data to the dc
                cc1.cmd('cat cc1_payload.txt | nc -u -w 1 {} 12345'.format(dc.IP())) # send data as UDP
                print(f"cc1: Sent UDP packet at {time.time()}")
                time.sleep(1)
                cc2.cmd('cat cc2_payload.txt | nc -u -w 1 {} 12345'.format(dc.IP()))
                print(f"cc2: Sent UDP packet at {time.time()}")
                time.sleep(1)
                cc3.cmd('cat cc3_payload.txt | nc -u -w 1 {} 12345'.format(dc.IP()))
                print(f"cc3: Sent UDP packet at {time.time()}")
                time.sleep(1)
                # Delete the file
                cc1.cmd('rm cc1.pcap')
                cc2.cmd('rm cc2.pcap')
                cc2.cmd('rm cc3.pcap')
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

            enhanced_switch11.send_health_parameters(cc1)
            print(f"Switch 11 sent health parameters to cc1")
            time.sleep(1)
            enhanced_switch12.send_health_parameters(cc1)
            print(f"Switch 12 sent health parameters to cc1")
            time.sleep(1)
            enhanced_switch21.send_health_parameters(cc2)
            print(f"Switch 21 sent health parameters to cc2")
            time.sleep(1)
            enhanced_switch22.send_health_parameters(cc2)
            print(f"Switch 22 sent health parameters to cc2")
            time.sleep(1)
            enhanced_switch31.send_health_parameters(cc3)
            print(f"Switch 31 sent health parameters to cc3")
            time.sleep(1)
            enhanced_switch32.send_health_parameters(cc3)
            print(f"Switch 32 sent health parameters to cc3")
            time.sleep(1)

            enhanced_router1.send_health_parameters(cc1)
            print(f"Router 1 sent health parameters to cc1")
            time.sleep(1)
            enhanced_router2.send_health_parameters(cc2)
            print(f"Router 2 sent health parameters to cc2")
            time.sleep(1)
            enhanced_router3.send_health_parameters(cc3)
            print(f"Router 3 sent health parameters to cc3")
            time.sleep(1)

            enhanced_router1.send_routing_parameters(cc1)
            print(f"Router 1 sent routing parameters to cc1")
            time.sleep(1)
            enhanced_router2.send_routing_parameters(cc2)
            print(f"Router 2 sent routing parameters to cc2")
            time.sleep(1)
            enhanced_router3.send_routing_parameters(cc3)
            print(f"Router 3 sent routing parameters to cc3")
            time.sleep(1)


        except KeyboardInterrupt:
            print("Stopping telemetry...")
            break


    cc1.cmd('killall tcpdump')
    cc1.cmd('python3 packet_processor.py cc1.pcap cc1')
    cc2.cmd('killall tcpdump')
    cc2.cmd('python3 packet_processor.py cc2.pcap cc2')
    cc3.cmd('killall tcpdump')
    cc3.cmd('python3 packet_processor.py cc3.pcap cc2')


    h12.cmd('killall iperf')
    h22.cmd('killall iperf')
    h32.cmd('killall iperf')
    


    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    simpleTest()
