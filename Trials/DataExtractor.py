from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost, Host, OVSKernelSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info
import time
import subprocess
import re

class HealthMonitoringSwitch(OVSKernelSwitch):
    "Custom switch that captures health parameters."

    def __init__(self, name, **params):
        super().__init__(name, **params)
        self.rx_errors = {}
        self.tx_errors = {}
        self.last_stats_time = None
        self.initial_stats = {}

    def start(self, *args, **kwargs):
        super().start(*args, **kwargs)
        self.reset_error_counters()
        self.capture_initial_stats()
        self.last_stats_time = time.time()

    def reset_error_counters(self):
        """Resets the error counters for all ports."""
        for port in self.ports:
            if port != self.name:
                self.rx_errors[port] = 0
                self.tx_errors[port] = 0

    def capture_initial_stats(self):
        """Captures the initial port statistics."""
        self.initial_stats = self._get_port_stats()

    def _get_port_stats(self):
        """Retrieves current port statistics using ovs-ofctl."""
        stats = {}
        output = self.cmd(f'ovs-ofctl dump-ports {self.name}')
        info(f"--- Output of ovs-ofctl dump-ports on {self.name} ---\n{output}\n--- End of Output ---")  # Debug output
        for line in output.splitlines():
            if 'port ' in line:
                parts = line.split()
                info(f"Processing line: {line}")  # Debug output
                port_num = None
                if len(parts) > 1:
                    if parts[1] == 'LOCAL:':
                        port_num = 0  # Assign 0 for the LOCAL port
                        info(f"  Identified LOCAL port as port number: {port_num}") # Debug output
                    elif '"' in parts[1]:
                        interface_name_with_colon = parts[1].strip('"')
                        interface_name = interface_name_with_colon.split(':')[0]
                        info(f"  Found interface name: {interface_name}") # Debug output
                        if self.name in interface_name and 'eth' in interface_name:
                            try:
                                port_num = int(interface_name.split('eth')[1])
                                info(f"    Inferred port number from interface name: {port_num}") # Debug output
                            except ValueError:
                                info(f"    Could not infer port number from '{interface_name}'.") # Debug output
                        else:
                            info(f"    Interface name '{interface_name}' does not match expected pattern.") # Debug output
                    elif parts[1].isdigit():
                        port_num = int(parts[1])
                        info(f"  Extracted port number (direct): {port_num}") # Debug output
                    else:
                        info(f"  Could not identify port information in '{parts[1]}'.") # Debug output

                if port_num is not None:
                    rx_packets_match = re.search(r'rx pkts=(\d+)', line)
                    rx_bytes_match = re.search(r'rx bytes=(\d+)', line)
                    tx_packets_match = re.search(r'tx pkts=(\d+)', line)
                    tx_bytes_match = re.search(r'tx bytes=(\d+)', line)
                    rx_errors_match = re.search(r'errs=(\d+)', line) # Changed to 'errs'
                    tx_errors_match = re.search(r'errs=\d+, .* tx pkts=\d+, bytes=\d+, drop=\d+, errs=(\d+)', line) # More specific TX error match

                    rx_errors = int(rx_errors_match.group(1)) if rx_errors_match else 0
                    tx_errors = int(tx_errors_match.group(1)) if tx_errors_match else 0

                    if all([rx_packets_match, rx_bytes_match, tx_packets_match, tx_bytes_match]):
                        stats[port_num] = {
                            'rx_packets': int(rx_packets_match.group(1)),
                            'rx_bytes': int(rx_bytes_match.group(1)),
                            'tx_packets': int(tx_packets_match.group(1)),
                            'tx_bytes': int(tx_bytes_match.group(1)),
                            'rx_errors': rx_errors,
                            'tx_errors': tx_errors,
                        }
                        info(f"    Successfully parsed stats for port {port_num}: {stats[port_num]}") # Debug output
                    else:
                        info(f"    Could not parse all stats for line: {line}") # Debug output
                else:
                    info(f"    Skipping line as port number could not be identified.") # Debug output
        return stats

    def get_health_parameters(self, duration=5):
        """Measures and returns health parameters for the switch ports."""
        if self.last_stats_time is None:
            print(f"Warning: {self.name} hasn't been started properly for health monitoring.")
            return {}

        current_time = time.time()
        elapsed_time = current_time - self.last_stats_time
        if elapsed_time < duration:
            time.sleep(duration - elapsed_time)
            current_time = time.time()
            elapsed_time = current_time - self.last_stats_time

        current_stats = self._get_port_stats()
        health_data = {}

        for port, current in current_stats.items():
            if port in self.initial_stats:
                initial = self.initial_stats[port]
                rx_packet_rate = (current['rx_packets'] - initial['rx_packets']) / elapsed_time
                rx_byte_rate = (current['rx_bytes'] - initial['rx_bytes']) / elapsed_time
                tx_packet_rate = (current['tx_packets'] - initial['tx_packets']) / elapsed_time
                tx_byte_rate = (current['tx_bytes'] - initial['tx_bytes']) / elapsed_time
                rx_error_rate = (current['rx_errors'] - initial['rx_errors']) / elapsed_time
                tx_error_rate = (current['tx_errors'] - initial['tx_errors']) / elapsed_time

                health_data[port] = {
                    'rx_packet_rate': rx_packet_rate,
                    'rx_byte_rate': rx_byte_rate,
                    'tx_packet_rate': tx_packet_rate,
                    'tx_byte_rate': tx_byte_rate,
                    'rx_error_rate': rx_error_rate,
                    'tx_error_rate': tx_error_rate,
                }
            else:
                health_data[port] = {"error": "Initial stats not available"}

        self.initial_stats = current_stats  # Update initial stats for the next measurement
        self.last_stats_time = current_time
        return health_data

class SimpleTopo(Topo):
    "Simple topology with two hosts connected by a switch."

    def __init__(self, **opts):
        Topo.__init__(self, **opts)

        # Add hosts
        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')

        # Add switch (using our custom HealthMonitoringSwitch)
        s1 = self.addSwitch('s1', cls=HealthMonitoringSwitch)

        # Add links
        self.addLink(h1, s1, cls=TCLink, bw=10, delay='5ms', loss=0, max_queue_size=1000)
        self.addLink(h2, s1, cls=TCLink, bw=10, delay='5ms', loss=0, max_queue_size=1000)

def measure_latency(net, h1, h2, count=5):
    """Measures latency between two hosts using ping."""
    h1_node = net.get(h1)
    h2_node = net.get(h2)
    latencies = []
    for _ in range(count):
        output = h1_node.cmd(f'ping -c 1 {h2_node.IP()}')
        match = re.search(r'time=(.*?)\s*ms', output)
        if match:
            latencies.append(float(match.group(1)))
        time.sleep(0.1)  # Small delay between pings
    if latencies:
        return sum(latencies) / len(latencies)
    return None

def measure_bandwidth(net, h1_name, h2_name, duration=5):
    """Measures bandwidth between two hosts using iperf."""
    h1 = net.get(h1_name)
    h2 = net.get(h2_name)
    print(f"Starting iperf server on {h2.name}...")
    server_process = h2.popen('iperf -s -p 5001')
    time.sleep(0.5)  # Give server a little time to start

    print(f"Running iperf client on {h1.name} connecting to {h2.IP()}...")
    client_output = h1.cmd(f'iperf -c {h2.IP()} -p 5001 -t {duration} -i 1')

    server_process.terminate()  # Terminate the iperf server process
    bandwidth = None
    for line in client_output.splitlines():
        match = re.search(r'\[.*?\]\s*\d+\.\d+-\d+\.\d+\s*sec\s*(\d+\.?\d*)\s*Mbits/sec', line)
        if match:
            bandwidth = float(match.group(1))
            break  # Take the last reported bandwidth

    if bandwidth is not None:
        print(f"Average bandwidth from {h1.name} to {h2.name}: {bandwidth:.2f} Mbit/s")
    else:
        print(f"Could not measure bandwidth between {h1.name} and {h2.name}.")
    return bandwidth

def get_uptime():
    """Gets the system uptime."""
    with open('/proc/uptime', 'r') as f:
        uptime_seconds = float(f.readline().split()[0])
        return uptime_seconds

def get_flow_count(net, switch_name='s1'):
    """Retrieves the number of flow entries in the switch."""
    switch = net.get(switch_name)
    if not switch:
        print(f"Switch {switch_name} not found.")
        return None

    output = switch.cmd(f'ovs-ofctl dump-flows {switch.name}')
    # Each flow entry typically starts with "cookie="
    flow_count = output.count('cookie=')
    print(f"\n--- Switch {switch_name} Flow Count ---")
    print(f"Number of flows: {flow_count}")
    return flow_count

if __name__ == '__main__':
    setLogLevel('info')
    topo = SimpleTopo()
    net = Mininet(topo, host=Host, link=TCLink)
    net.start()

    h1, h2 = net.get('h1', 'h2')
    s1 = net.get('s1')

    print("\n--- Measuring Network Parameters ---")

    # Latency
    latency = measure_latency(net, 'h1', 'h2')
    if latency is not None:
        print(f"Latency (average): {latency:.2f} ms")
    else:
        print("Could not measure latency.")

    # Bandwidth (measure before continuous traffic)
    bandwidth = measure_bandwidth(net, 'h1', 'h2')
    if bandwidth is not None:
        print(f"Bandwidth (approximate): {bandwidth:.2f} Mbit/s")
    else:
        print("Could not measure bandwidth.")

    # Uptime (of the Mininet host OS)
    uptime_seconds = get_uptime()
    uptime_minutes = uptime_seconds / 60
    uptime_hours = uptime_minutes / 60
    print(f"Uptime (of Mininet host): {int(uptime_hours)} hours, {int(uptime_minutes % 60)} minutes, {int(uptime_seconds % 60)} seconds")

    # Start continuous iperf traffic in the background
    info("\n*** Starting continuous iperf traffic from h1 to h2...\n")
    iperf_server_process = h2.popen('iperf -s -p 5001')
    time.sleep(0.5) # Give server time to start
    iperf_client_process = h1.popen('iperf -c %s -p 5001 -b 5M' % h2.IP()) # Send at 5 Mbps

    try:
        print("\n--- Printing Health Parameters every 5 seconds ---")
        while True:
            print(f"\n--- Health Data at {time.strftime('%Y-%m-%d %H:%M:%S')} ---")
            health_data = s1.get_health_parameters(duration=5)
            # for port, data in health_data.items():
            #     if isinstance(data, dict):
            #         print(f"  Port {port}:")
            #         print(f"    RX Packet Rate: {data['rx_packet_rate']:.2f} p/s")
            #         print(f"    RX Byte Rate: {data['rx_byte_rate']:.2f} B/s")
            #         print(f"    TX Packet Rate: {data['tx_packet_rate']:.2f} p/s")
            #         print(f"    TX Byte Rate: {data['tx_byte_rate']:.2f} B/s")
            #         print(f"    RX Error Rate: {data['rx_error_rate']:.2f} errors/s")
            #         print(f"    TX Error Rate: {data['tx_error_rate']:.2f} errors/s")
            #     else:
            #         # print(f"  Port {port}: {data}")
            #         print("HAHA")
            time.sleep(5)

    except KeyboardInterrupt:
        print("\n--- Stopping Health Parameter Monitoring ---")
    finally:
        # Clean up the background iperf processes
        iperf_client_process.terminate()
        iperf_server_process.terminate()
        net.stop()
