from mininet.node import Node
from mininet.log import info
import time
import re
import statistics

# Helper Functions

def measure_buffer_occupancy(device, interface):
    """
    Attempts to calculate buffer occupancy for a given device interface.
    Uses the 'tc -s qdisc' command on the specified interface.
    """
    output = device.cmd(f"tc -s qdisc show dev {interface}")
    match = re.search(r'backlog\s+(\d+)b', output)
    if match:
        return int(match.group(1))
    else:
        return None

def measure_cpu_utilization(device, duration):
    """
    Measures CPU usage over a specified duration by reading /proc/stat.
    The CPU usage is computed as the percentage of non-idle time.
    """
    stat1 = device.cmd("cat /proc/stat")
    # Parse first line (aggregated over all cores)
    fields = stat1.splitlines()[0].split()
    # Typically, fields[1]=user, [2]=nice, [3]=system, [4]=idle, [5]=iowait, etc.
    # For a simple calculation, we consider idle time as the sum of idle and iowait.
    idle1 = int(fields[4])
    if len(fields) > 5:
        idle1 += int(fields[5])
    total1 = sum(int(x) for x in fields[1:])
    
    time.sleep(duration)
    
    stat2 = device.cmd("cat /proc/stat")
    fields2 = stat2.splitlines()[0].split()
    idle2 = int(fields2[4])
    if len(fields2) > 5:
        idle2 += int(fields2[5])
    total2 = sum(int(x) for x in fields2[1:])
    
    total_diff = total2 - total1
    idle_diff = idle2 - idle1
    if total_diff > 0:
        cpu_usage_percent = 100 * (total_diff - idle_diff) / total_diff
    else:
        cpu_usage_percent = 0
    return cpu_usage_percent

def measure_memory_usage(device):
    """
    Measures memory utilization by reading /proc/meminfo.
    Returns the percentage of used memory.
    """
    meminfo = device.cmd("cat /proc/meminfo")
    total = None
    available = None
    for line in meminfo.splitlines():
        if line.startswith("MemTotal:"):
            total = int(line.split()[1])  # in kB
        elif line.startswith("MemAvailable:"):
            available = int(line.split()[1])
    if total is not None and available is not None:
        used = total - available
        return 100 * used / total
    return None

# Health Monitoring for Routers

class HealthMonitoringRouter(Node):
    """Custom router that captures interface and system health parameters."""
    def __init__(self, name, **params):
        super().__init__(name, **params)
        self.last_stats_time = None
        self.initial_stats = {}

    def start(self):
        """
        Initialize the router, record the current time, and capture initial stats.
        """
        # Perform any necessary initialization for the router
        self.last_stats_time = time.time()  # Record the start time
        self.capture_initial_stats()  # Capture initial interface statistics
        info(f"{self.name} initialized and ready for health monitoring.\n")

    def capture_initial_stats(self):
        """
        Capture initial interface statistics for rate calculations.
        """
        self.initial_stats = self._get_interface_stats()

    def _get_interface_stats(self):
        """
        Retrieve interface statistics using 'ip -s link show' for each interface.
        Returns a dictionary keyed by interface name.
        """
        stats = {}
        for intf in self.intfList():
            output = self.cmd(f"ip -s link show dev {intf}")
            lines = output.splitlines()
            rx_values = None
            tx_values = None
            # Look for 'RX:' and 'TX:' headers; assume the next non-empty line is the value line.
            for i, line in enumerate(lines):
                if line.strip().startswith("RX:"):
                    if i+1 < len(lines):
                        rx_line = lines[i+1].strip()
                        rx_values = rx_line.split()
                if line.strip().startswith("TX:"):
                    if i+1 < len(lines):
                        tx_line = lines[i+1].strip()
                        tx_values = tx_line.split()
            if rx_values and len(rx_values) >= 3:
                rx_bytes   = int(rx_values[0])
                rx_packets = int(rx_values[1])
                rx_errors  = int(rx_values[2])
            else:
                rx_bytes = rx_packets = rx_errors = 0
            if tx_values and len(tx_values) >= 3:
                tx_bytes   = int(tx_values[0])
                tx_packets = int(tx_values[1])
                tx_errors  = int(tx_values[2])
            else:
                tx_bytes = tx_packets = tx_errors = 0

            stats[intf] = {
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
        Calculate per-interface rates and system resource usage over the given duration.
        Also returns CPU and memory utilization.
        Returns a dictionary keyed by interface name and overall system parameters.
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
        current_stats = self._get_interface_stats()
        health_data = {}
        for intf, current in current_stats.items():
            if intf in self.initial_stats:
                initial = self.initial_stats[intf]
                rx_packet_rate = (current['rx_packets'] - initial['rx_packets']) / elapsed_time
                rx_byte_rate   = (current['rx_bytes']   - initial['rx_bytes']) / elapsed_time
                tx_packet_rate = (current['tx_packets'] - initial['tx_packets']) / elapsed_time
                tx_byte_rate   = (current['tx_bytes']   - initial['tx_bytes']) / elapsed_time
                rx_error_rate  = (current['rx_errors']  - initial['rx_errors']) / elapsed_time
                tx_error_rate  = (current['tx_errors']  - initial['tx_errors']) / elapsed_time
                avg_thr_bps = ((rx_byte_rate + tx_byte_rate) * 8) / 2
                avg_thr_mbps = avg_thr_bps / 1e6
                rx_util = (rx_byte_rate * 8 / link_capacity_bps) * 100
                tx_util = (tx_byte_rate * 8 / link_capacity_bps) * 100
                # Calculate buffer occupancy for the interface
                buffer_occ = measure_buffer_occupancy(self, intf)
                health_data[intf] = {
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
                health_data[intf] = {"error": "Initial stats not available"}
        self.initial_stats = current_stats
        self.last_stats_time = current_time

        # Add overall system health parameters
        health_data['cpu_usage_percent'] = measure_cpu_utilization(self, 1)
        health_data['memory_usage_percent'] = measure_memory_usage(self)
        return health_data

    def get_routing_information(self):
        """
        Retrieve routing table information using the 'ip route' command.
        Removes ANSI color codes from the output and parses each line into
        a dictionary with keys: destination, gateway, device, protocol, scope, and src.
        Returns a dictionary containing a list of routing entries and the raw output.
        """
        import re
        # Regex pattern to remove ANSI escape sequences
        ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
        
        routing_info = {}
        output = self.cmd("ip route")
        # Clean the output by removing ANSI codes
        output_clean = ansi_escape.sub('', output)
        if not output_clean:
            routing_info["error"] = "No routing information available"
            return routing_info

        routing_table = []
        for line in output_clean.splitlines():
            line = line.strip()
            # Remove surrounding square brackets if present
            if line.startswith('[') and line.endswith(']'):
                line = line[1:-1].strip()
            tokens = line.split()
            entry = {}
            if tokens:
                entry["destination"] = tokens[0]
            # Initialize defaults for optional values
            entry["gateway"] = "N/A"
            entry["device"] = "N/A"
            entry["protocol"] = "N/A"
            entry["scope"] = "N/A"
            entry["src"] = "N/A"
            # Process tokens looking for keywords and their following values
            i = 0
            while i < len(tokens):
                token = tokens[i]
                if token == "via" and i+1 < len(tokens):
                    entry["gateway"] = tokens[i+1]
                    i += 2
                    continue
                elif token == "dev" and i+1 < len(tokens):
                    entry["device"] = tokens[i+1]
                    i += 2
                    continue
                elif token == "proto" and i+1 < len(tokens):
                    entry["protocol"] = tokens[i+1]
                    i += 2
                    continue
                elif token == "scope" and i+1 < len(tokens):
                    entry["scope"] = tokens[i+1]
                    i += 2
                    continue
                elif token == "src" and i+1 < len(tokens):
                    entry["src"] = tokens[i+1]
                    i += 2
                    continue
                else:
                    i += 1
            entry["raw"] = line
            routing_table.append(entry)
        routing_info["routing_table"] = routing_table
        routing_info["raw_output"] = output_clean

        ospf_output = self.cmd('vtysh -c "show ip ospf neighbor"')
        ospf_neighbors = 0
        ospf_state = "Down"
        for line in ospf_output.strip().splitlines():
            if "Full" in line or "2-Way" in line:
                ospf_neighbors += 1
                ospf_state = "Full"
        routing_info["Ospf Neighbors"] = ospf_neighbors
        routing_info["Ospf State"] = ospf_state

   
        bgp_output = self.cmd('vtysh -c "show ip bgp summary"')
        bgp_peer = "unknown"
        bgp_state = "Idle"
        learned_routes = 0
        for line in bgp_output.strip().splitlines():
            if line.startswith("Neighbor") or line.strip() == "":
                continue
            parts = line.split()
            if len(parts) >= 9 and parts[0].count('.') == 3:
                bgp_peer = parts[0]
                try:
                    learned_routes = int(parts[8])
                    bgp_state = "Established"
                except ValueError:
                    bgp_state = parts[8]

        routing_info["BGP Data"] = f"BGP Peer {bgp_peer}: {bgp_state}, Learned Routes: {learned_routes}"
        return routing_info
