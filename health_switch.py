#!/usr/bin/env python3
from mininet.node import OVSKernelSwitch
from mininet.log import info
import time
import re

class HealthMonitoringSwitch(OVSKernelSwitch):
    """Custom switch that captures health parameters."""
    def __init__(self, name, **params):
        super().__init__(name, **params)
        self.last_stats_time = None
        self.initial_stats = {}

    def start(self, *args, **kwargs):
        """Start the switch and record the current time."""
        super().start(*args, **kwargs)
        self.last_stats_time = time.time()

    def capture_initial_stats(self):
        """Capture initial port statistics for rate calculations."""
        self.initial_stats = self._get_port_stats()

    def _get_port_stats(self):
        """Retrieve current port statistics using ovs-ofctl."""
        stats = {}
        output = self.cmd(f'ovs-ofctl dump-ports {self.name}')
        # Split output into port sections:
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
        """
        Calculate per-port rates and error rates over the given duration.
        Returns a dictionary keyed by port number.
        """
        if self.last_stats_time is None:
            info(f"Warning: {self.name} hasn't been started properly for health monitoring.\n")
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
        self.initial_stats = current_stats
        self.last_stats_time = current_time
        return health_data
