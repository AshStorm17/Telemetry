from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.log import setLogLevel, info
from mininet.cli import CLI
import time
import threading
import os
from packet_processor import end2end_cc2dc

class MyTopo(Topo):
    "Simple topology example."

    def build(self):
        "Create custom topo."
        # Add hosts and switches
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        # Add link
        self.addLink(h1, h2)

def run_commands(h1, h2):
    """Runs the commands on h1 and h2."""
    def h1_send_udp():
        """Sends UDP packets from h1."""
        while True:
            if not os.path.exists("cc1_payload.txt"):
                with open("cc1_payload.txt", "w") as f:
                    f.write("DUMMY_PAYLOAD")
            h1.cmd('cat cc1_payload.txt | nc -u -w 1 {} 12345'.format(h2.IP()))
            print(f"h1: Sent UDP packet at {time.time()}")
            time.sleep(11)

    def h2_run_tcpdump():
        """Runs tcpdump on h2."""
        h2.cmd('tcpdump -i h2-eth0 udp port 12345 -w capture.pcap &')
        time.sleep(25)
        h2.cmd('kill %tcpdump')
        print("h2: tcpdump capture finished.")

    # Start tcpdump on h2 in a separate thread
    tcpdump_thread = threading.Thread(target=h2_run_tcpdump)
    tcpdump_thread.start()

    h1_send_udp()
    tcpdump_thread.join()
    print("Simulation complete.")

def run():
    "Create and run the mininet topology using a RemoteController."
    topo = MyTopo()
    net = Mininet(topo=topo, controller=RemoteController)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)
    net.start()

    h1, h2 = net.get('h1', 'h2')
    run_commands(h1, h2)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    end2end_cc2dc("all_packets.pcap", "cc1")
    run()
