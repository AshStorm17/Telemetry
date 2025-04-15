from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost, Host, Node
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
from health_firewall import HealthMonitoringFirewall
from hlp_firewall import *
from mininet.cli import CLI
import os


class CustomTopology(Topo):
    "Topology with DC, 3 CCs, Routers, and direct DC connection via dcs1."
    def __init__(self):
        Topo.__init__(self)

        # --- Central DC Infrastructure ---
        dc = self.addHost('dc', ip='10.0.100.1/24')
        dcs1 = self.addSwitch('dcs1') # Switch connecting DC and CCs

        # Link DC to the central switch
        self.addLink(dc, dcs1)


        cc1 = self.addHost('cc1', ip='10.0.1.1/24')
        cc2 = self.addHost('cc2', ip='10.0.2.1/24') 
        cc3 = self.addHost('cc3', ip='10.0.3.1/24') 


        r1 = self.addHost('r1', cls=HealthMonitoringRouter) 
        r2 = self.addHost('r2', cls=HealthMonitoringRouter) 

        # --- Cluster 1 Infrastructure (Subnet: 10.0.1.0/24) ---
        s1_cc1 = self.addSwitch('s1_cc1', cls = HealthMonitoringSwitch)
        s2_cc1 = self.addSwitch('s2_cc1', cls = HealthMonitoringSwitch)
        s1_cc1_h = self.addHost('s1_cc1_h', ip='10.0.1.10/24', defaultRoute='via 10.0.1.254')
        s2_cc1_h = self.addHost('s2_cc1_h', ip='10.0.1.11/24', defaultRoute='via 10.0.1.254')

        self.addLink(cc1, s1_cc1, intfName1='cc1-eth0')
        self.addLink(s1_cc1_h, s1_cc1)
        self.addLink(s2_cc1_h, s2_cc1)

        self.addLink(s1_cc1, r1, intfName2='r1-eth0', params2={'ip': '10.0.1.254/24'})
        self.addLink(s1_cc1, s2_cc1) # Connect switches within cluster
        # Add regular hosts
        for i in range(1, 9):
             host = self.addHost(f'h{i}_cc1', ip=f'10.0.1.{i+1}/24', defaultRoute='via 10.0.1.254')
             if i <= 4: self.addLink(host, s1_cc1)
             else: self.addLink(host, s2_cc1)

        # --- Cluster 2 Infrastructure (Subnet: 10.0.2.0/24) ---
        s1_cc2 = self.addSwitch('s1_cc2', cls = HealthMonitoringSwitch)
        s2_cc2 = self.addSwitch('s2_cc2', cls = HealthMonitoringSwitch)
        # These hosts need a default route via the router on their segment (use r1's IP for consistency)
        s1_cc2_h = self.addHost('s1_cc2_h', ip='10.0.2.10/24', defaultRoute='via 10.0.2.254')
        s2_cc2_h = self.addHost('s2_cc2_h', ip='10.0.2.11/24', defaultRoute='via 10.0.2.254')
        # Link cc2 (eth0) and telemetry hosts to local switches
        self.addLink(cc2, s1_cc2, intfName1='cc2-eth0')
        self.addLink(s1_cc2_h, s1_cc2)
        self.addLink(s2_cc2_h, s2_cc2)
        # Link Switches (s1 to routers, s2 to s1)
        self.addLink(s1_cc2, r1, intfName2='r1-eth1', params2={'ip': '10.0.2.254/24'}) # Connect CC2 switch to R1
        self.addLink(s1_cc2, r2, intfName2='r2-eth0', params2={'ip': '10.0.2.253/24'}) # Connect CC2 switch to R2
        self.addLink(s1_cc2, s2_cc2) # Connect switches within cluster
        # Add regular hosts
        for i in range(1, 9):
             # Default via R1's IP on this segment (10.0.2.254)
             host = self.addHost(f'h{i}_cc2', ip=f'10.0.2.{i+1}/24', defaultRoute='via 10.0.2.254')
             if i <= 4: self.addLink(host, s1_cc2)
             else: self.addLink(host, s2_cc2)

        # --- Cluster 3 Infrastructure (Subnet: 10.0.3.0/24) ---
        s1_cc3 = self.addSwitch('s1_cc3', cls = HealthMonitoringSwitch)
        s2_cc3 = self.addSwitch('s2_cc3', cls = HealthMonitoringSwitch)
        # These hosts need a default route via the router on their segment
        s1_cc3_h = self.addHost('s1_cc3_h', ip='10.0.3.10/24', defaultRoute='via 10.0.3.254')
        s2_cc3_h = self.addHost('s2_cc3_h', ip='10.0.3.11/24', defaultRoute='via 10.0.3.254')
        # Link cc3 (eth0) and telemetry hosts to local switches
        self.addLink(cc3, s1_cc3, intfName1='cc3-eth0')
        self.addLink(s1_cc3_h, s1_cc3)
        self.addLink(s2_cc3_h, s2_cc3)
        # Link Switches (s1 to router, s2 to s1)
        self.addLink(s1_cc3, r2, intfName2='r2-eth1', params2={'ip': '10.0.3.254/24'}) # Connect CC3 switch to R2
        self.addLink(s1_cc3, s2_cc3) # Connect switches within cluster
        # Add regular hosts
        for i in range(1, 9):
             host = self.addHost(f'h{i}_cc3', ip=f'10.0.3.{i+1}/24', defaultRoute='via 10.0.3.254')
             if i <= 4: self.addLink(host, s1_cc3)
             else: self.addLink(host, s2_cc3)

        # --- Connect Cluster Centers to Central DC Switch (dcs1) ---
        self.addLink(cc1, dcs1, intfName1='cc1-eth1', params1={'ip': '10.0.100.11/24'})
        self.addLink(cc2, dcs1, intfName1='cc2-eth1', params1={'ip': '10.0.100.12/24'})
        self.addLink(cc3, dcs1, intfName1='cc3-eth1', params1={'ip': '10.0.100.13/24'})




def simpleTest():
    topo = CustomTopology()
    net = Mininet(topo=topo, link=TCLink, controller=None)
    net.addController('pox', controller=RemoteController, ip='127.0.0.1', port=6633)
    net.start()

    # Special Hosts
    dc = net.get('dc')
    cc1 = net.get('cc1')
    cc2 = net.get('cc2')
    cc3 = net.get('cc3')
    r1 = net.get('r1')
    r2 = net.get('r2')

    # Switch-Associated Hosts - Cluster 1
    s1_cc1_h = net.get('s1_cc1_h')
    s2_cc1_h = net.get('s2_cc1_h')
    s1_cc1 = net.get("s1_cc1")
    s2_cc1 = net.get("s2_cc1")
    # Regular Hosts - Cluster 1
    h1_cc1 = net.get('h1_cc1')
    h2_cc1 = net.get('h2_cc1')
    h3_cc1 = net.get('h3_cc1')
    h4_cc1 = net.get('h4_cc1')
    h5_cc1 = net.get('h5_cc1')
    h6_cc1 = net.get('h6_cc1')
    h7_cc1 = net.get('h7_cc1')
    h8_cc1 = net.get('h8_cc1')

    # Switch-Associated Hosts - Cluster 2
    s1_cc2_h = net.get('s1_cc2_h')
    s2_cc2_h = net.get('s2_cc2_h')
    s1_cc2 = net.get("s1_cc2")
    s2_cc2 = net.get("s2_cc2")
    # Regular Hosts - Cluster 2
    h1_cc2 = net.get('h1_cc2')
    h2_cc2 = net.get('h2_cc2')
    h3_cc2 = net.get('h3_cc2')
    h4_cc2 = net.get('h4_cc2')
    h5_cc2 = net.get('h5_cc2')
    h6_cc2 = net.get('h6_cc2')
    h7_cc2 = net.get('h7_cc2')
    h8_cc2 = net.get('h8_cc2')

    # Switch-Associated Hosts - Cluster 3
    s1_cc3_h = net.get('s1_cc3_h')
    s2_cc3_h = net.get('s2_cc3_h')
    s1_cc3 = net.get("s1_cc3")
    s2_cc3 = net.get("s2_cc3")
    # Regular Hosts - Cluster 3
    h1_cc3 = net.get('h1_cc3')
    h2_cc3 = net.get('h2_cc3')
    h3_cc3 = net.get('h3_cc3')
    h4_cc3 = net.get('h4_cc3')
    h5_cc3 = net.get('h5_cc3')
    h6_cc3 = net.get('h6_cc3')
    h7_cc3 = net.get('h7_cc3')
    h8_cc3 = net.get('h8_cc3')
    
    for cc in [cc1, cc2, cc3]:
        cc.cmd('sysctl net.ipv4.ip_forward=1')

    # 2. Ensure Router Interfaces are UP

    r1.cmd('ip link set r1-eth0 up') # To CC1 Switch (s1_cc1)
    r1.cmd('ip link set r1-eth1 up') # To CC2 Switch (s1_cc2)
    r2.cmd('ip link set r2-eth0 up') # To CC2 Switch (s1_cc2)
    r2.cmd('ip link set r2-eth1 up') # To CC3 Switch (s1_cc3)

    # 3. Add Static Routes on Routers (r1, r2) for Inter-Cluster Traffic
    # R1 needs route to CC3 network (10.0.3.0/24) via R2's IP on the shared CC2 segment (10.0.2.253)
    r1.cmd('ip route add 10.0.3.0/24 via 10.0.2.253 dev r1-eth1')
    # R2 needs route to CC1 network (10.0.1.0/24) via R1's IP on the shared CC2 segment (10.0.2.254)
    r2.cmd('ip route add 10.0.1.0/24 via 10.0.2.254 dev r2-eth0')

    # cc1: Needs routes to cc2 and cc3 via r1 (10.0.1.254) on its local interface (cc1-eth0)
    cc1.cmd('ip route add 10.0.2.0/24 via 10.0.1.254 dev cc1-eth0')
    cc1.cmd('ip route add 10.0.3.0/24 via 10.0.1.254 dev cc1-eth0') # r1 knows how to reach 10.0.3.0/24

    # cc2: Needs routes to cc1 (via r1 @ 10.0.2.254) and cc3 (via r2 @ 10.0.2.253) on local interface (cc2-eth0)
    cc2.cmd('ip route add 10.0.1.0/24 via 10.0.2.254 dev cc2-eth0')
    cc2.cmd('ip route add 10.0.3.0/24 via 10.0.2.253 dev cc2-eth0')

    # cc3: Needs routes to cc1 and cc2 via r2 (10.0.3.254) on local interface (cc3-eth0)
    cc3.cmd('ip route add 10.0.2.0/24 via 10.0.3.254 dev cc3-eth0')
    cc3.cmd('ip route add 10.0.1.0/24 via 10.0.3.254 dev cc3-eth0') # r2 knows how to reach 10.0.1.0/24

    # 5. Add Static Routes on DC Host
    # info("Adding static routes on dc...\n")
    dc.cmd('ip route add 10.0.1.0/24 via 10.0.100.11') # Reach CC1 via cc1's DC-facing IP
    dc.cmd('ip route add 10.0.2.0/24 via 10.0.100.12') # Reach CC2 via cc2's DC-facing IP
    dc.cmd('ip route add 10.0.3.0/24 via 10.0.100.13') # Reach CC3 via cc3's DC-facing IP

    # time.sleep(2)
    # net.pingAll()


    
     # fw1 = net.get("fw1")
    # fw1.cmd('sysctl -w net.ipv4.ip_forward=1')
    # fw1.capture_initial_stats()
    # # Optional: Add iptables rules to fw1 here if needed
    # # Example: Allow traffic between h11 and the rest of the network connected via s11
    # fw1.cmd('iptables -A FORWARD -i fw1-eth0 -o fw1-eth1 -j ACCEPT')
    # fw1.cmd('iptables -A FORWARD -i fw1-eth1 -o fw1-eth0 -j ACCEPT')

    # h11_ip = net.get('h11').IP()
    # h12_ip = net.get('h12').IP()

    # info(f"*** Starting tcpdump on fw1 interfaces fw1-eth0 and fw1-eth1 filtering for {h11_ip} <-> {h12_ip}\n")
    # # Capture on interface connected to h11
    # fw1.cmd(f'tcpdump -i fw1-eth0 -n -w fw1_eth0_capture.pcap "host {h11_ip} and host {h12_ip}" &')
    # # Capture on interface connected to s11
    # fw1.cmd(f'tcpdump -i fw1-eth1 -n -w fw1_eth1_capture.pcap "host {h11_ip} and host {h12_ip}" &')

 

        

    h2_cc1.cmd('iperf -s -u -i 1 > iperf_server_output &')
    time.sleep(1)
    h2_cc3.cmd('iperf -s -u -i 1 > iperf_server_output &')
    time.sleep(1)
    h2_cc2.cmd('iperf -s -u -i 1 > iperf_server_output &')
    time.sleep(1)



    h1_cc1.cmd('iperf -c ' + h2_cc1.IP() + ' -u -b 1k &')
    time.sleep(1)
    h3_cc1.cmd('iperf -c ' + h2_cc2.IP() + ' -u -b 1k &')
    time.sleep(1)
    h4_cc1.cmd('iperf -c ' + h2_cc3.IP() + ' -u -b 1k &')
    time.sleep(1)
    h5_cc1.cmd('iperf -c ' + h2_cc1.IP() + ' -u -b 1k &')
    time.sleep(1)
    h6_cc1.cmd('iperf -c ' + h2_cc2.IP() + ' -u -b 1k &')
    time.sleep(1)
    h7_cc1.cmd('iperf -c ' + h2_cc3.IP() + ' -u -b 1k &')
    time.sleep(1)
    h8_cc1.cmd('iperf -c ' + h2_cc1.IP() + ' -u -b 1k &')
    time.sleep(1)

    
    h1_cc2.cmd('iperf -c ' + h2_cc2.IP() + ' -u -b 1k &')
    time.sleep(1)
    h3_cc2.cmd('iperf -c ' + h2_cc1.IP() + ' -u -b 1k &')
    time.sleep(1)
    h4_cc2.cmd('iperf -c ' + h2_cc3.IP() + ' -u -b 1k &')
    time.sleep(1)
    h5_cc2.cmd('iperf -c ' + h2_cc2.IP() + ' -u -b 1k &')
    time.sleep(1)
    h6_cc2.cmd('iperf -c ' + h2_cc1.IP() + ' -u -b 1k &')
    time.sleep(1)
    h7_cc2.cmd('iperf -c ' + h2_cc3.IP() + ' -u -b 1k &')
    time.sleep(1)
    h8_cc2.cmd('iperf -c ' + h2_cc2.IP() + ' -u -b 1k &')
    time.sleep(1)

    
    h1_cc3.cmd('iperf -c ' + h2_cc3.IP() + ' -u -b 1k &')
    time.sleep(1)
    h3_cc3.cmd('iperf -c ' + h2_cc1.IP() + ' -u -b 1k &')
    time.sleep(1)
    h4_cc3.cmd('iperf -c ' + h2_cc2.IP() + ' -u -b 1k &')
    time.sleep(1)
    h5_cc3.cmd('iperf -c ' + h2_cc3.IP() + ' -u -b 1k &')
    time.sleep(1)
    h6_cc3.cmd('iperf -c ' + h2_cc1.IP() + ' -u -b 1k &')
    time.sleep(1)
    h7_cc3.cmd('iperf -c ' + h2_cc2.IP() + ' -u -b 1k &')
    time.sleep(1)
    h8_cc3.cmd('iperf -c ' + h2_cc3.IP() + ' -u -b 1k &')
    time.sleep(1)



    enhanced_switch11 = EnhancedSwitch(s1_cc1_h, s1_cc1, parameters={})
    enhanced_switch12 = EnhancedSwitch(s2_cc1_h, s2_cc1, parameters={})
    enhanced_switch21 = EnhancedSwitch(s1_cc2_h, s1_cc2, parameters={})
    enhanced_switch22 = EnhancedSwitch(s2_cc2_h, s2_cc2, parameters={})
    enhanced_switch31 = EnhancedSwitch(s1_cc3_h, s1_cc3, parameters={})
    enhanced_switch32 = EnhancedSwitch(s2_cc3_h, s2_cc3, parameters={})

    enhanced_router1 = EnhancedRouter(r1, parameters={})
    enhanced_router2 = EnhancedRouter(r2, parameters={})
    enhanced_router1.start()
    enhanced_router2.start()

    # enhanced_firewall1 = EnhancedFirewall(fw1,parameters={})
    # enhanced_firewall1.start()

    dc.cmd('tcpdump -i any udp port 12345 -w capture.pcap &')
    cc1.cmd('tcpdump -i any -v -w cc1.pcap not icmp6 and not port 5353 and not arp &')
    cc2.cmd('tcpdump -i any -v -w cc2.pcap not icmp6 and not port 5353 and not arp &')
    cc3.cmd('tcpdump -i any -v -w cc3.pcap not icmp6 and not port 5353 and not arp &')
    time.sleep(2)
    print("Starting Telemetry...")

    ticks = 0
    randf_count = 0      
    while True:
        time.sleep(0.5)
        try:
            ticks += 1
            randf_count += 1
            ticks %= 10
            if ticks%2 == 0:
                # End tcpdump of cc
                cc1.cmd('kill %tcpdump')
                cc2.cmd('kill %tcpdump')
                cc3.cmd('kill %tcpdump')
                # Read the file cc1.pcap and send a "Hello" message to the dc from cc
                out = os.system('python3 packet_processor.py cc1.pcap cc1 &')
                out1 = os.system('python3 packet_processor.py cc2.pcap cc2 &')
                out2 = os.system('python3 packet_processor.py cc3.pcap cc3 &')
                # Send the data to the dc
                cc1.cmd('cat cc1_payload.txt | nc -u -w 1 {} 12345'.format(dc.IP())) # send data as UDP
                print(f"cc1: Sent UDP packet at {time.time()}")
                time.sleep(0.1)
                cc2.cmd('cat cc2_payload.txt | nc -u -w 1 {} 12345'.format(dc.IP()))
                print(f"cc2: Sent UDP packet at {time.time()}")
                time.sleep(0.1)
                cc3.cmd('cat cc3_payload.txt | nc -u -w 1 {} 12345'.format(dc.IP()))
                print(f"cc3: Sent UDP packet at {time.time()}")
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
            time.sleep(0.1)
            enhanced_switch12.send_health_parameters(cc1)
            print(f"Switch 12 sent health parameters to cc1")
            time.sleep(0.1)
            enhanced_switch21.send_health_parameters(cc2)
            print(f"Switch 21 sent health parameters to cc2")
            time.sleep(0.1)
            enhanced_switch22.send_health_parameters(cc2)
            print(f"Switch 22 sent health parameters to cc2")
            time.sleep(0.1)
            enhanced_switch31.send_health_parameters(cc3)
            print(f"Switch 31 sent health parameters to cc3")
            time.sleep(0.1)
            enhanced_switch32.send_health_parameters(cc3)
            print(f"Switch 32 sent health parameters to cc3")
            time.sleep(0.1)

            enhanced_router1.send_health_parameters(cc1)
            print(f"Router 1 sent health parameters to cc1")
            time.sleep(0.1)
            enhanced_router2.send_health_parameters(cc2)
            print(f"Router 2 sent health parameters to cc2")
            time.sleep(0.1)

            enhanced_router1.send_routing_parameters(cc1)
            print(f"Router 1 sent routing parameters to cc1")
            time.sleep(0.1)
            enhanced_router2.send_routing_parameters(cc2)
            print(f"Router 2 sent routing parameters to cc2")
            time.sleep(0.1)

            # enhanced_firewall1.send_firewall_parameters(cc1)
            # print(f"Router 3 sent firewall parameters to cc1")
            # time.sleep(0.1)


        except KeyboardInterrupt:
            print("Stopping telemetry...")
            break


    cc1.cmd('killall tcpdump')
    cc1.cmd('python3 packet_processor.py cc1.pcap cc1')
    cc2.cmd('killall tcpdump')
    cc2.cmd('python3 packet_processor.py cc2.pcap cc2')
    cc3.cmd('killall tcpdump')
    cc3.cmd('python3 packet_processor.py cc3.pcap cc2')
    # fw1.cmd('killall tcpdump')


    h2_cc1.cmd('killall iperf')
    h2_cc2.cmd('killall iperf')
    h2_cc3.cmd('killall iperf')
    


    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    simpleTest()
