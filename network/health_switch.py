from mininet.node import OVSKernelSwitch
from mininet.log import info
import time
import re
import statistics

class HealthMonitoringSwitch(OVSKernelSwitch):
    def __init__(self, name, **params):
        super().__init__(name, **params)
        self.last_stats_time = None
        self.initial_stats = {}

    # def start(self, *args, **kwargs):
    #     """Start the switch and record the current time."""
    #     super().start(*args, **kwargs)
    #     self.last_stats_time = time.time()

    def capture_initial_stats(self):
        self.initial_stats = self._get_port_stats()
        self.last_stats_time = None

    def _get_port_stats(self):
        stats = {}
        output = self.cmd(f'ovs-ofctl dump-ports {self.name}')
        port_sections = []
        current_section = []
        for line in output.splitlines():
            if line.strip().startswith("port "):
                if current_section:
                    port_sections.append(current_section)
                current_section = [line]
            else:
                if line.strip():
                    current_section.append(line)
        if current_section:
            port_sections.append(current_section)
        
        # Process each port section
        for section in port_sections:
            port_line = section[0]
            port_match = re.search(r'port\s+(?:"([^"]+)"|(\d+)):', port_line)
            if not port_match:
                continue
            port_num = None
            if port_match.group(2) and port_match.group(2).isdigit():
                port_num = int(port_match.group(2))
            elif port_match.group(1):
                if port_match.group(1) == "LOCAL":
                    port_num = 0
                elif 'eth' in port_match.group(1):
                    try:
                        port_num = int(port_match.group(1).split('-eth')[1])
                    except (ValueError, IndexError):
                        continue

            if port_num is None:
                continue

            section_text = "\n".join(section)
            rx_packets = int(re.search(r'rx\s+pkts=(\d+)', section_text).group(1) or 0)
            rx_bytes = int(re.search(r'rx\s+pkts=\d+,\s*bytes=(\d+)', section_text).group(1) or 0)
            tx_packets = int(re.search(r'tx\s+pkts=(\d+)', section_text).group(1) or 0)
            tx_bytes = int(re.search(r'tx\s+pkts=\d+,\s*bytes=(\d+)', section_text).group(1) or 0)
            rx_errors = int(re.search(r'rx.*?errs=(\d+)', section_text).group(1) or 0)
            tx_errors = int(re.search(r'tx.*?errs=(\d+)', section_text).group(1) or 0)
            
            stats[port_num] = {
                'rx_packets': rx_packets,
                'rx_bytes': rx_bytes,
                'tx_packets': tx_packets,
                'tx_bytes': tx_bytes,
                'rx_errors': rx_errors,
                'tx_errors': tx_errors,
            }
        return stats

    def get_health_parameters(self, duration=5, link_capacity_bps=10e6):
        if self.last_stats_time is None:
            self.initial_stats = self._get_port_stats()
            self.last_stats_time = time.time()
            time.sleep(duration)

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
                avg_thr_bps = ((rx_byte_rate + tx_byte_rate) * 8) / 2
                avg_thr_mbps = avg_thr_bps / 1e6
                rx_util = (rx_byte_rate * 8 / link_capacity_bps) * 100
                tx_util = (tx_byte_rate * 8 / link_capacity_bps) * 100
       
                buffer_occ = measure_buffer_occupancy(self, port)
                health_data[port] = {
                    'rx_packet_rate': rx_packet_rate,
                    'rx_byte_rate': rx_byte_rate,
                    'tx_packet_rate': tx_packet_rate,
                    'tx_byte_rate': tx_byte_rate,
                    'throughput (mbps)': avg_thr_mbps,
                    'rx_utilization': rx_util,
                    'tx_utilization': tx_util,
                    'rx_error_rate': rx_error_rate,
                    'tx_error_rate': tx_error_rate,
                    'buffer_occupancy': buffer_occ
                }
            else:
                health_data[port] = {"error": "Initial stats not available"}
        self.initial_stats = current_stats
        self.last_stats_time = current_time


        return health_data



def measure_buffer_occupancy(switch, port):
    iface = f"{switch.name}-eth{port}"
    output = switch.cmd(f"tc -s qdisc show dev {iface}")
    match = re.search(r'backlog\s+(\d+)b', output)
    if match:
        occupancy_bytes = int(match.group(1))
        return occupancy_bytes
    else:
        return None
    