import time
import re
import subprocess
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost, Host, OVSKernelSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.clean import cleanup
from advanced_metrics import (
    get_advanced_switch_metrics, get_advanced_host_metrics, 
    analyze_path_quality, analyze_protocol_distribution,
    monitor_hardware_resources, analyze_long_term_stability
)

# Helper functions for parsing and calculations:
def parse_int(command_output):
    """Extract integer from command output."""
    try:
        # Find the first number in the output
        match = re.search(r'\d+', command_output)
        if match:
            return int(match.group())
        return 0
    except:
        return 0

def get_message_rate(switch):
    """Calculate message processing rate."""
    try:
        # Just included the simplified version: just count the number of messages processed
        # To be modified as we go along
        before = parse_int(switch.cmd("ovs-ofctl show " + switch.name + " | grep 'n_recv'"))
        time.sleep(1)
        after = parse_int(switch.cmd("ovs-ofctl show " + switch.name + " | grep 'n_recv'"))
        return after - before
    except:
        return 0

def check_hardware_offload(switch):
    """Check if hardware offloading is enabled."""
    try:
        output = switch.cmd("ovs-vsctl get Open_vSwitch . other_config:hw-offload")
        return {
            'enabled': 'true' in output.lower(),
            'capabilities': check_offload_capabilities(switch)
        }
    except:
        return {'enabled': False}

def check_offload_capabilities(switch):
    """Check hardware offload capabilities.
        technique where certain network processing tasks are transferred from the CPU to the network interface card (NIC), which can:

Improve network performance
Reduce CPU utilization
Increase throughput
Lower latency

    """
    try:
        output = switch.cmd("ethtool -k " + switch.intfs[1].name)
        return {
            'tx': 'tx-checksumming: on' in output,
            'rx': 'rx-checksumming: on' in output,
            'tso': 'tcp-segmentation-offload: on' in output
        }
    except:
        return {}

def count_network_interrupts(interrupts_output):
    try:
        # Look for lines with eth or net in them
        count = 0
        for line in interrupts_output.split('\n'):
            if 'eth' in line.lower() or 'net' in line.lower() or 'nic' in line.lower():
                count += 1
        return count
    except:
        return 0

def analyze_memory_fragmentation(host):
    try:
        buddyinfo = host.cmd("cat /proc/buddyinfo")
        # Count the number of free pages of different sizes
        sizes = [0] * 11  # 11 different sizes in buddyinfo
        for line in buddyinfo.split('\n'):
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) > 14:  # Ensure there are enough fields
                for i in range(4, 15):  # Typically fields 4-14 contain the counts
                    if i - 4 < len(sizes):
                        sizes[i - 4] += int(parts[i])
        return {
            'free_chunks_by_size': sizes,
            'fragmentation_index': calculate_fragmentation_index(sizes)
        }
    except Exception as e:
        return {'error': str(e)}

def calculate_fragmentation_index(sizes):
    if not sizes or sum(sizes) == 0:
        return 0
    
    # Weight larger chunks more heavily
    weighted_sum = sum(size * (2 ** i) for i, size in enumerate(sizes))
    max_possible = sum(sizes) * (2 ** (len(sizes) - 1))
    
    return 1 - (weighted_sum / max_possible) if max_possible > 0 else 0

def get_tcp_stat(host, stat_name):
    try:
        output = host.cmd(f"cat /proc/net/snmp | grep -A1 '^Tcp:' | tail -1")
        headers = host.cmd(f"cat /proc/net/snmp | grep '^Tcp:' | head -1").split()[1:]
        values = output.split()[1:]
        
        for i, header in enumerate(headers):
            if header == stat_name and i < len(values):
                return int(values[i])
        return 0
    except:
        return 0

def extract_mtu(tracepath_output):  # maximum transmission unit
    try:
        mtu_match = re.search(r'MTU=(\d+)', tracepath_output)
        return int(mtu_match.group(1)) if mtu_match else None
    except:
        return None

def check_path_asymmetry(net, src, dst):
    """Check for asymmetric routing."""
    try:
        # Trace path in both directions
        forward_path = net.get(src).cmd(f"traceroute -n {net.get(dst).IP()}")
        reverse_path = net.get(dst).cmd(f"traceroute -n {net.get(src).IP()}")
        
        # Extract hops
        forward_hops = extract_traceroute_hops(forward_path)
        reverse_hops = extract_traceroute_hops(reverse_path)
        
        if not forward_hops or not reverse_hops:
            return None
            
        # Compare paths (oversimplified - would need more robust comparison)
        forward_set = set(forward_hops)
        reverse_set = set(reverse_hops)
        
        shared_hops = len(forward_set.intersection(reverse_set))
        total_unique_hops = len(forward_set.union(reverse_set))
        
        return 1 - (shared_hops / total_unique_hops) if total_unique_hops > 0 else 0
    except:
        return None

def extract_traceroute_hops(traceroute_output):
    """Extract hop IP addresses from traceroute output."""
    hops = []
    for line in traceroute_output.split('\n'):
        # Match IP address patterns
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
        if ip_match:
            hops.append(ip_match.group(1))
    return hops

def measure_tcp_handshake_time(src_host, dst_host):
    try:
        # Use tcpdump to capture handshake packets
        dst_host.cmd(f"nc -l 12345 > /dev/null &")
        time.sleep(0.5)
        
        # Start capture
        src_host.cmd(f"tcpdump -i {src_host.defaultIntf().name} -n 'tcp port 12345' -ttt > /tmp/handshake.txt &")
        time.sleep(0.5)
        
        # Initiate connection
        start = time.time()
        src_host.cmd(f"echo -n | nc {dst_host.IP()} 12345 -w 1")
        
        # Stop capture
        src_host.cmd("pkill -f 'tcpdump -i'")
        dst_host.cmd("pkill -f 'nc -l'")
        
        # Analyze capture
        capture = src_host.cmd("cat /tmp/handshake.txt")
        syn_time = extract_timestamp(capture, "SYN ")
        ack_time = extract_timestamp(capture, "ACK ")
        
        if syn_time and ack_time:
            return ack_time - syn_time
        else:
            return time.time() - start  # Fallback
    except:
        return None

def extract_timestamp(capture, pattern):
    """Extract timestamp from tcpdump output."""
    try:
        for line in capture.split('\n'):
            if pattern in line:
                # tcpdump -ttt gives timestamps in seconds since previous packet
                time_match = re.match(r'(\d+\.\d+)', line)
                if time_match:
                    return float(time_match.group(1))
        return None
    except:
        return None

def calculate_std_dev(values):
    if not values or len(values) < 2:
        return 0
    
    mean = sum(values) / len(values)
    variance = sum((x - mean) ** 2 for x in values) / len(values)
    return variance ** 0.5

def analyze_trend(values):
    if not values or len(values) < 2:
        return {'trend': 'stable', 'change_rate': 0}
    
    # Simple linear regression
    n = len(values)
    x = list(range(n))
    
    # Calculate slope
    x_mean = sum(x) / n
    y_mean = sum(values) / n
    
    numerator = sum((x[i] - x_mean) * (values[i] - y_mean) for i in range(n))
    denominator = sum((x[i] - x_mean) ** 2 for i in range(n))
    
    if denominator == 0:
        slope = 0
    else:
        slope = numerator / denominator
    
    # Determine trend
    if abs(slope) < 0.01:
        trend = 'stable'
    elif slope > 0:
        trend = 'increasing'
    else:
        trend = 'decreasing'
    
    # Calculate relative change
    first, last = values[0], values[-1]
    if first == 0:
        change_rate = 0 if last == 0 else float('inf')
    else:
        change_rate = (last - first) / first
    
    return {'trend': trend, 'slope': slope, 'change_rate': change_rate}

def sum_all_errors(metrics):
    total = 0
    
    # Sum host errors
    for host, host_metrics in metrics.get('hosts', {}).items():
        if 'interfaces' in host_metrics:
            for iface, iface_metrics in host_metrics['interfaces'].items():
                total += iface_metrics.get('rx_errors', 0)
                total += iface_metrics.get('tx_errors', 0)
    
    # Sum switch errors
    for switch, switch_metrics in metrics.get('switches', {}).items():
        for port, port_metrics in switch_metrics.items():
            if isinstance(port_metrics, dict) and 'rx_error_rate' in port_metrics:
                total += port_metrics.get('rx_error_rate', 0)
                total += port_metrics.get('tx_error_rate', 0)
    
    return total

def detect_periodic_patterns(metrics_history):
    # Simple autocorrelation-based detection
    # This is a placeholder - real implementation would be more complex
    return {'detected': False, 'period': None}

def find_metric_correlations(metrics_history):
    # Placeholder - real implementation would calculate Pearson correlation
    return {'high_correlations': []}

def parse_cpu_per_core(top_output):
    cores = []
    for line in top_output.split('\n'):
        if line.startswith('%Cpu'):
            # Extract the user+system utilization
            match = re.search(r'(\d+\.\d+).*?us.*?(\d+\.\d+).*?sy', line)
            if match:
                user = float(match.group(1))
                system = float(match.group(2))
                cores.append(user + system)
    return cores

def parse_io_wait(iostat_output):
    """Parse IO wait time from iostat output."""
    for line in iostat_output.split('\n'):
        fields = line.split()
        if len(fields) >= 4:
            try:
                # iowait is typically the 4th field in iostat -c output
                return float(fields[3])
            except:
                pass
    return 0


class HealthMonitoringSwitch(OVSKernelSwitch):
    def __init__(self, name, **params):
        super().__init__(name, **params)
        self.rx_errors = {}
        self.tx_errors = {}
        self.last_stats_time = None
        self.initial_stats = {}
        self.flow_stats_history = []
        self.buffer_stats_history = []
        self.queue_stats_history = []
        self.last_cpu_stat = None
        self.last_cpu_time = None

    def start(self, *args, **kwargs):
        super().start(*args, **kwargs)
        self.reset_error_counters()
        self.capture_initial_stats()
        self.last_stats_time = time.time()
        self.last_cpu_stat = self._get_cpu_stats()
        self.last_cpu_time = time.time()

    def reset_error_counters(self):
        """for all ports."""
        for port in self.ports:
            if port != self.name:
                self.rx_errors[port] = 0
                self.tx_errors[port] = 0

    def capture_initial_stats(self):
        """Captures the initial port statistics."""
        self.initial_stats = self._get_port_stats()
        # Give a moment for the network to stabilize after capturing stats
        time.sleep(0.5)

    def _get_port_stats(self):
        """Retrieves current port statistics using ovs-ofctl."""
        stats = {}
        output = self.cmd(f'ovs-ofctl dump-ports {self.name}')
        info(f"--- Output of ovs-ofctl dump-ports on {self.name} ---\n{output}\n--- End of Output ---")
        
        # First identify port sections
        port_sections = []
        current_section = []
        in_port_section = False
        
        for line in output.splitlines():
            # Start of a new port section
            if line.strip().startswith("port "):
                if in_port_section and current_section:
                    port_sections.append(current_section)
                current_section = [line]
                in_port_section = True
            elif in_port_section and line.strip():
                current_section.append(line)
        
        # Add the last section if any
        if in_port_section and current_section:
            port_sections.append(current_section)
            
        # Process each port section
        for section in port_sections:
            if not section:
                continue
                
            # Extract port number/name
            port_line = section[0]
            port_match = re.search(r'port\s+(?:"([^"]+)"|(\d+)):', port_line)
            
            if not port_match:
                continue
                
            port_name = port_match.group(1)
            port_num_str = port_match.group(2)
            
            port_num = None
            if port_num_str and port_num_str.isdigit():
                port_num = int(port_num_str)
            elif port_name:
                if port_name == "LOCAL":
                    port_num = 0
                elif 'eth' in port_name:
                    try:
                        port_num = int(port_name.split('-eth')[1])
                    except (ValueError, IndexError):
                        continue
            
            if port_num is None:
                continue
                
            # Join all lines for easier regex
            section_text = '\n'.join(section)
            
            # Extract statistics
            rx_packets = 0
            rx_bytes = 0
            tx_packets = 0 
            tx_bytes = 0
            rx_errors = 0
            tx_errors = 0
            
            # RX stats - match the exact format in the output
            rx_pkts_match = re.search(r'rx pkts=(\d+)', section_text)
            if rx_pkts_match:
                rx_packets = int(rx_pkts_match.group(1))
                
            # Look for format "rx pkts=X, bytes=Y"
            rx_bytes_match = re.search(r'rx pkts=\d+, bytes=(\d+)', section_text)
            if rx_bytes_match:
                rx_bytes = int(rx_bytes_match.group(1))
                
            rx_errs_match = re.search(r'errs=(\d+)', section_text)
            if rx_errs_match:
                rx_errors = int(rx_errs_match.group(1))
                
            # TX stats - match the exact format in the output
            tx_pkts_match = re.search(r'tx pkts=(\d+)', section_text)
            if tx_pkts_match:
                tx_packets = int(tx_pkts_match.group(1))
                
            # Look for format "tx pkts=X, bytes=Y"
            tx_bytes_match = re.search(r'tx pkts=\d+, bytes=(\d+)', section_text)
            if tx_bytes_match:
                tx_bytes = int(tx_bytes_match.group(1))
                
            # Match TX errors on the TX line
            tx_errs_match = re.search(r'tx .*errs=(\d+)', section_text)
            if tx_errs_match:
                tx_errors = int(tx_errs_match.group(1))
            
            # Save the stats
            stats[port_num] = {
                'rx_packets': rx_packets,
                'rx_bytes': rx_bytes,
                'tx_packets': tx_packets,
                'tx_bytes': tx_bytes,
                'rx_errors': rx_errors,
                'tx_errors': tx_errors,
            }
            
            info(f"    Successfully parsed stats for port {port_num}: {stats[port_num]}")
        
        return stats

    def _get_cpu_stats(self):
        """Get CPU stats for the switch process."""
        try:
            # Get the PID of the OVS process for this switch
            pid_output = self.cmd(f"pgrep -f {self.name}")
            pids = pid_output.strip().split()
            if not pids:
                return None
                
            # Use the first PID
            pid = pids[0].strip()
            if not pid:
                return None
                
            # Get CPU stats for the process
            cpu_info = self.cmd(f"ps -p {pid} -o %cpu,%mem,vsz,rss,stat")
            lines = cpu_info.strip().split('\n')
            if len(lines) < 2:
                return None
                
            # Parse the stats (typically in format: %CPU %MEM VSZ RSS STAT)
            stats = lines[1].split()
            if len(stats) >= 5:
                return {
                    'cpu_percent': float(stats[0]),
                    'memory_percent': float(stats[1]),
                    'vsz': int(stats[2]),
                    'rss': int(stats[3]),
                    'state': stats[4]
                }
            
            return None
        except Exception as e:
            info(f"Error getting CPU stats: {e}")
            return None
            
    def _get_flow_table_stats(self):
        output = self.cmd(f'ovs-ofctl dump-flows {self.name}')
        flow_count = output.count('cookie=')
        
        # Get more detailed stats
        output = self.cmd(f'ovs-ofctl dump-aggregate {self.name}')
        
        packet_count = 0
        byte_count = 0
        flow_count_from_agg = 0
        
        # Parse the aggregate output
        if 'packet_count=' in output:
            packet_match = re.search(r'packet_count=(\d+)', output)
            if packet_match:
                packet_count = int(packet_match.group(1))
                
        if 'byte_count=' in output:
            byte_match = re.search(r'byte_count=(\d+)', output)
            if byte_match:
                byte_count = int(byte_match.group(1))
                
        if 'flow_count=' in output:
            flow_match = re.search(r'flow_count=(\d+)', output)
            if flow_match:
                flow_count_from_agg = int(flow_match.group(1))
                
        # In case aggregate couldn't get flow count
        if flow_count_from_agg == 0:
            flow_count_from_agg = flow_count
            
        return {
            'flow_count': flow_count,
            'packet_count': packet_count,
            'byte_count': byte_count,
            'timestamp': time.time()
        }
        
    def _get_queue_stats(self):
        """for all ports."""
        output = self.cmd(f'ovs-ofctl -O OpenFlow13 queue-stats {self.name}')
        queue_stats = {}
        
        # Parse queue stats
        for line in output.splitlines():
            if 'port=' in line and 'queue=' in line:
                port_match = re.search(r'port="?(\d+)"?', line)
                queue_match = re.search(r'queue="?(\d+)"?', line)
                tx_bytes_match = re.search(r'tx_bytes=(\d+)', line)
                tx_packets_match = re.search(r'tx_packets=(\d+)', line)
                tx_errors_match = re.search(r'tx_errors=(\d+)', line)
                
                if port_match and queue_match:
                    port = int(port_match.group(1))
                    queue = int(queue_match.group(1))
                    
                    if port not in queue_stats:
                        queue_stats[port] = {}
                        
                    queue_stats[port][queue] = {
                        'tx_bytes': int(tx_bytes_match.group(1)) if tx_bytes_match else 0,
                        'tx_packets': int(tx_packets_match.group(1)) if tx_packets_match else 0,
                        'tx_errors': int(tx_errors_match.group(1)) if tx_errors_match else 0
                    }
                    
        return queue_stats
        
    def _get_buffer_stats(self):
        # This command might not work on all OVS versions
        output = self.cmd(f'ovs-ofctl -O OpenFlow13 queue-stats {self.name}')
        buffer_free = None
        buffer_used = None
        
        # Try a different approach - get memory usage of the OVS process
        mem_stats = self._get_cpu_stats()
        if mem_stats:
            return {
                'buffer_free': 0,  # Not directly available
                'buffer_used': 0,  # Not directly available
                'process_memory_kb': mem_stats['rss'],
                'timestamp': time.time()
            }
            
        return {
            'buffer_free': 0,
            'buffer_used': 0,
            'process_memory_kb': 0,
            'timestamp': time.time()
        }

    def get_health_parameters(self, duration=5):
        if self.last_stats_time is None:
            print(f"Warning: {self.name} hasn't been started properly for health monitoring.")
            return {}

        current_time = time.time()
        elapsed_time = current_time - self.last_stats_time
        if elapsed_time < duration:
            time.sleep(duration - elapsed_time)
            current_time = time.time()
            elapsed_time = current_time - self.last_stats_time

        # Get port statistics
        current_stats = self._get_port_stats()
        
        # Get additional health metrics
        flow_stats = self._get_flow_table_stats()
        self.flow_stats_history.append(flow_stats)
        if len(self.flow_stats_history) > 10:  # Keep only last 10 entries
            self.flow_stats_history.pop(0)
            
        # Get queue statistics
        queue_stats = self._get_queue_stats()
        self.queue_stats_history.append({
            'stats': queue_stats,
            'timestamp': time.time()
        })
        if len(self.queue_stats_history) > 10:
            self.queue_stats_history.pop(0)
            
        # Get buffer statistics
        buffer_stats = self._get_buffer_stats()
        self.buffer_stats_history.append(buffer_stats)
        if len(self.buffer_stats_history) > 10:
            self.buffer_stats_history.pop(0)
            
        # Get CPU usage
        current_cpu_stat = self._get_cpu_stats()
        current_cpu_time = time.time()
        
        cpu_utilization = None
        if self.last_cpu_stat and current_cpu_stat:
            cpu_utilization = current_cpu_stat['cpu_percent']
            
        self.last_cpu_stat = current_cpu_stat
        self.last_cpu_time = current_cpu_time

        # Calculate port-specific health metrics
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

                # Calculate additional metrics
                rx_pps_to_bps_ratio = 0
                if rx_packet_rate > 0:
                    rx_pps_to_bps_ratio = rx_byte_rate / rx_packet_rate
                    
                tx_pps_to_bps_ratio = 0
                if tx_packet_rate > 0:
                    tx_pps_to_bps_ratio = tx_byte_rate / tx_packet_rate
                
                health_data[port] = {
                    'rx_packet_rate': rx_packet_rate,
                    'rx_byte_rate': rx_byte_rate,
                    'rx_kb_rate': rx_byte_rate / 1024,
                    'tx_packet_rate': tx_packet_rate,
                    'tx_byte_rate': tx_byte_rate,
                    'tx_kb_rate': tx_byte_rate / 1024,
                    'rx_error_rate': rx_error_rate,
                    'tx_error_rate': tx_error_rate,
                    'rx_avg_packet_size': rx_pps_to_bps_ratio,
                    'tx_avg_packet_size': tx_pps_to_bps_ratio,
                    'queue_stats': queue_stats.get(port, {}) if queue_stats else {},
                }
            else:
                health_data[port] = {"error": "Initial stats not available"}

        # Add overall switch metrics
        health_data['switch'] = {
            'flow_stats': flow_stats,
            'buffer_stats': buffer_stats,
            'cpu_utilization': cpu_utilization,
            'memory_usage': current_cpu_stat['memory_percent'] if current_cpu_stat else None,
            'process_state': current_cpu_stat['state'] if current_cpu_stat else None,
        }

        self.initial_stats = current_stats  # Update initial stats for the next measurement
        self.last_stats_time = current_time
        return health_data

class ExtendedHost(Host):
    """Extended host with health monitoring capabilities."""
    
    def __init__(self, name, **params):
        super().__init__(name, **params)
        self.last_cpu_stat = None
        self.last_cpu_time = None
        
    def get_health_parameters(self):
        """Get health metrics for this host."""
        health_data = {}
        
        # CPU utilization
        health_data['cpu'] = self._get_cpu_info()
        
        # Memory usage
        health_data['memory'] = self._get_memory_info()
        
        # Network interface stats
        health_data['interfaces'] = self._get_interface_stats()
        
        # Socket statistics
        health_data['sockets'] = self._get_socket_stats()
        
        # TCP statistics
        health_data['tcp_stats'] = self._get_tcp_stats()
        
        # Process information
        health_data['processes'] = self._get_process_info()
        
        return health_data
        
    def _get_cpu_info(self):
        """Get CPU utilization."""
        try:
            # Using /proc/stat to get system-wide CPU stats
            cpu_info = self.cmd("cat /proc/stat | grep '^cpu '")
            if not cpu_info:
                return {'error': 'Could not read CPU info'}
                
            # Parse CPU info
            fields = cpu_info.split()
            if len(fields) < 8:
                return {'error': 'Invalid CPU info format'}
                
            # Combine all CPU time fields
            user = int(fields[1])
            nice = int(fields[2])
            system = int(fields[3])
            idle = int(fields[4])
            iowait = int(fields[5])
            irq = int(fields[6])
            softirq = int(fields[7])
            
            # Calculate CPU usage if we have previous data
            if self.last_cpu_stat:
                prev = self.last_cpu_stat
                prev_total = prev['total']
                prev_idle = prev['idle']
                
                current_total = user + nice + system + idle + iowait + irq + softirq
                total_diff = current_total - prev_total
                idle_diff = idle - prev_idle
                
                if total_diff > 0:
                    cpu_usage = 100.0 * (1.0 - (idle_diff / total_diff))
                else:
                    cpu_usage = 0.0
                    
                # Store current values for next time
                self.last_cpu_stat = {
                    'user': user,
                    'nice': nice,
                    'system': system,
                    'idle': idle,
                    'iowait': iowait,
                    'irq': irq,
                    'softirq': softirq,
                    'total': current_total,
                    'timestamp': time.time()
                }
                
                return {
                    'usage_percent': cpu_usage,
                    'user': user,
                    'system': system,
                    'idle': idle,
                    'iowait': iowait
                }
            else:
                # First time, just store values
                total = user + nice + system + idle + iowait + irq + softirq
                self.last_cpu_stat = {
                    'user': user,
                    'nice': nice,
                    'system': system,
                    'idle': idle,
                    'iowait': iowait,
                    'irq': irq,
                    'softirq': softirq,
                    'total': total,
                    'timestamp': time.time()
                }
                
                return {
                    'usage_percent': 0.0,  # First time, no previous data
                    'user': user,
                    'system': system,
                    'idle': idle,
                    'iowait': iowait
                }
        except Exception as e:
            return {'error': f'Error getting CPU info: {str(e)}'}
            
    def _get_memory_info(self):
        try:
            mem_info = self.cmd("cat /proc/meminfo")
            lines = mem_info.splitlines()
            
            memory_stats = {}
            for line in lines:
        """Get socket statistics."""
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    if 'kB' in value:
                        value = value.replace('kB', '').strip()
                        memory_stats[key] = int(value)
                        
            # Calculate memory usage percentages
            if 'MemTotal' in memory_stats and memory_stats['MemTotal'] > 0:
                used_mem = memory_stats.get('MemTotal', 0) - memory_stats.get('MemFree', 0)
                memory_stats['UsedPercent'] = 100.0 * (used_mem / memory_stats['MemTotal'])
                
                # Add buffer/cache usage
                buffered = memory_stats.get('Buffers', 0)
                cached = memory_stats.get('Cached', 0)
                used_with_buffers = used_mem - (buffered + cached)
                
                memory_stats['UsedWithoutBuffersPercent'] = 100.0 * (used_with_buffers / memory_stats['MemTotal'])
                
            return memory_stats
        except Exception as e:
            return {'error': f'Error getting memory info: {str(e)}'}
            
    def _get_interface_stats(self):
        try:
            # Read interface statistics from /proc/net/dev
            net_info = self.cmd("cat /proc/net/dev")
            lines = net_info.splitlines()
            
            interface_stats = {}
            # Skip first two header lines
            for line in lines[2:]:
                parts = line.split(':')
                if len(parts) != 2:
                    continue
                    
                interface = parts[0].strip()
                data = parts[1].strip().split()
                
                if len(data) >= 16:  # Ensure we have enough data fields
                    interface_stats[interface] = {
                        'rx_bytes': int(data[0]),
                        'rx_packets': int(data[1]),
                        'rx_errors': int(data[2]),
                        'rx_dropped': int(data[3]),
                        'rx_fifo_errors': int(data[4]),
                        'rx_frame_errors': int(data[5]),
                        'rx_compressed': int(data[6]),
                        'rx_multicast': int(data[7]),
                        'tx_bytes': int(data[8]),
                        'tx_packets': int(data[9]),
                        'tx_errors': int(data[10]),
                        'tx_dropped': int(data[11]),
                        'tx_fifo_errors': int(data[12]),
                        'tx_collisions': int(data[13]),
                        'tx_carrier_errors': int(data[14]),
                        'tx_compressed': int(data[15])
                    }
                    
            return interface_stats
        except Exception as e:
            return {'error': f'Error getting interface stats: {str(e)}'}
            
    def _get_socket_stats(self):
        try:
            # Using ss command to get socket stats summary
            socket_stats = self.cmd("ss -s")
            
            # Parse the output into a structured format
            result = {'raw_output': socket_stats}
            
            # Extract total socket count
            total_match = re.search(r'Total:\s*(\d+)', socket_stats)
            if total_match:
                result['total'] = int(total_match.group(1))
                
            # Extract TCP socket counts
            tcp_match = re.search(r'TCP:\s*(\d+)', socket_stats)
            if tcp_match:
                result['tcp'] = int(tcp_match.group(1))
                
            # Extract UDP socket counts
            udp_match = re.search(r'UDP:\s*(\d+)', socket_stats)
            if udp_match:
                result['udp'] = int(udp_match.group(1))
                
            # Extract TCP states if available
            tcp_states = {}
            state_matches = re.finditer(r'(\w+)\s+(\d+)', socket_stats)
            for match in state_matches:
                state, count = match.groups()
                if state not in ['Total', 'TCP', 'UDP']:  # Avoid duplicating the main counts
                    tcp_states[state] = int(count)
                    
            if tcp_states:
                result['tcp_states'] = tcp_states
                
            return result
        except Exception as e:
            return {'error': f'Error getting socket stats: {str(e)}'}
            
    def _get_tcp_stats(self):
        """from /proc/net/tcp."""
        try:
            tcp_info = self.cmd("cat /proc/net/snmp | grep -A 1 '^Tcp:'")
            lines = tcp_info.splitlines()
            
            if len(lines) < 2:
                return {'error': 'Could not read TCP stats'}
                
            # Parse header and data lines
            header = lines[0].split()[1:]  # Skip 'Tcp:'
            data = lines[1].split()[1:]    # Skip 'Tcp:'
            
            tcp_stats = {}
            for i, key in enumerate(header):
                if i < len(data):
                    tcp_stats[key] = int(data[i])
                    
            # Calculate retransmission rate
            if 'OutSegs' in tcp_stats and tcp_stats['OutSegs'] > 0 and 'RetransSegs' in tcp_stats:
                tcp_stats['RetransmissionRate'] = 100.0 * (tcp_stats['RetransSegs'] / tcp_stats['OutSegs'])
                
            return tcp_stats
        except Exception as e:
            return {'error': f'Error getting TCP stats: {str(e)}'}
            
    def _get_process_info(self):
        """Get information about top CPU consuming processes."""
        try:
            # Get top 5 CPU consuming processes
            process_info = self.cmd("ps -eo pid,ppid,cmd,%cpu,%mem --sort=-%cpu | head -n 6")
            lines = process_info.splitlines()
            
            if len(lines) < 2:  # Need at least header and one process
                return {'error': 'Could not get process info'}
                
            # Parse header and data lines
            processes = []
            header = lines[0].split()
            
            for i in range(1, len(lines)):
                # Handle command with spaces
                line = lines[i].strip()
                if not line:
                    continue
                    
                # Split line and reconstruct command with spaces
                parts = line.split()
                if len(parts) < 5:  # Need at least PID, PPID, CMD, %CPU, %MEM
                    continue
                    
                pid = int(parts[0])
                ppid = int(parts[1])
                
                # Combine parts between command and %CPU
                cmd_parts = []
                cpu_mem_found = False
                for j in range(2, len(parts)):
                    if re.match(r'^\d+\.\d+$', parts[j]):  # Found %CPU
                        cpu_index = j
                        cpu_mem_found = True
                        break
                    cmd_parts.append(parts[j])
                    
                if not cpu_mem_found or cpu_index >= len(parts) - 1:
                    continue
                    
                cmd = ' '.join(cmd_parts)
                cpu_percent = float(parts[cpu_index])
                mem_percent = float(parts[cpu_index + 1])
                
                processes.append({
                    'pid': pid,
                    'ppid': ppid,
                    'command': cmd,
                    'cpu_percent': cpu_percent,
                    'memory_percent': mem_percent
                })
                
            return {'top_processes': processes}
        except Exception as e:
            return {'error': f'Error getting process info: {str(e)}'}

# Extend the SimpleTopo class to use our extended host
class EnhancedTopo(Topo):
    """Topology with extended health monitoring capabilities."""

    def __init__(self, **opts):
        Topo.__init__(self, **opts)

        # Add hosts (using our extended host class)
        h1 = self.addHost('h1', ip='10.0.0.1/24', cls=ExtendedHost)
        h2 = self.addHost('h2', ip='10.0.0.2/24', cls=ExtendedHost)

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

def measure_tcp_performance(net, src_host, dst_host, duration=5):
    """Measure TCP performance metrics between hosts."""
    src = net.get(src_host)
    dst = net.get(dst_host)
    
    # Start iperf server on destination host
    print(f"Starting iperf server on {dst.name} for TCP performance measurement...")
    server_process = dst.popen('iperf -s -p 5001')
    time.sleep(0.5)  # Give server time to start
    
    # Run iperf client with detailed statistics
    print(f"Running iperf client on {src.name} to measure TCP performance...")
    output = src.cmd(f'iperf -c {dst.IP()} -p 5001 -t {duration} -i 1')
    
    # Stop server
    server_process.terminate()
    
    # Parse results
    metrics = {
        'bandwidth': [],
        'jitter': [],
        'raw_output': output
    }
    
    for line in output.splitlines():
        # Match bandwidth measurements
        bw_match = re.search(r'\[\s*\d+\]\s+\d+\.\d+-\d+\.\d+\s+sec\s+\d+\s+\w+\s+(\d+\.?\d*)\s+\w+/sec', line)
        if bw_match:
            metrics['bandwidth'].append(float(bw_match.group(1)))
            
    # Calculate average bandwidth if measurements exist
    if metrics['bandwidth']:
        metrics['avg_bandwidth'] = sum(metrics['bandwidth']) / len(metrics['bandwidth'])
        metrics['max_bandwidth'] = max(metrics['bandwidth'])
        metrics['min_bandwidth'] = min(metrics['bandwidth'])
        
    return metrics

def measure_udp_performance(net, src_host, dst_host, bandwidth='10M', duration=5):
    """Measure UDP performance metrics between hosts including jitter and packet loss."""
    src = net.get(src_host)
    dst = net.get(dst_host)
    
    # Start iperf server on destination host with UDP mode
    print(f"Starting iperf server on {dst.name} for UDP performance measurement...")
    server_process = dst.popen('iperf -s -u -p 5002')
    time.sleep(0.5)  # Give server time to start
    
    # Run iperf client with UDP mode and specified bandwidth
    print(f"Running iperf client on {src.name} to measure UDP performance...")
    output = src.cmd(f'iperf -c {dst.IP()} -u -p 5002 -b {bandwidth} -t {duration} -i 1')
    
    # Stop server
    server_process.terminate()
    
    # Parse results
    metrics = {
        'bandwidth': [],
        'jitter': [],
        'packet_loss': None,
        'raw_output': output
    }
    
    for line in output.splitlines():
        # Look for summary line with loss information
        if 'datagrams received' in line:
            loss_match = re.search(r'(\d+)/(\d+) \((\d+\.?\d*)%\)', line)
            if loss_match:
                metrics['packet_loss'] = float(loss_match.group(3))
                
        # Match bandwidth and jitter measurements
        perf_match = re.search(r'\[\s*\d+\]\s+\d+\.\d+-\d+\.\d+\s+sec\s+\d+\s+\w+\s+(\d+\.?\d*)\s+\w+/sec\s+(\d+\.?\d*)\s+ms', line)
        if perf_match:
            metrics['bandwidth'].append(float(perf_match.group(1)))
            metrics['jitter'].append(float(perf_match.group(2)))
            
    # Calculate average metrics if measurements exist
    if metrics['bandwidth']:
        metrics['avg_bandwidth'] = sum(metrics['bandwidth']) / len(metrics['bandwidth'])
        
    if metrics['jitter']:
        metrics['avg_jitter'] = sum(metrics['jitter']) / len(metrics['jitter'])
        metrics['max_jitter'] = max(metrics['jitter'])
        
    return metrics

def measure_path_characteristics(net, src_host, dst_host, count=5):
    """Measure path characteristics including RTT, jitter, and path stability."""
    src = net.get(src_host)
    dst = net.get(dst_host)
    
    # Measure RTT (ping) statistics
    print(f"Measuring path characteristics from {src.name} to {dst.name}...")
    output = src.cmd(f'ping -c {count} {dst.IP()}')
    
    metrics = {
        'rtts': [],
        'raw_output': output
    }
    
    # Parse ping output
    for line in output.splitlines():
        rtt_match = re.search(r'time=(\d+\.?\d*) ms', line)
        if rtt_match:
            metrics['rtts'].append(float(rtt_match.group(1)))
            
    # Calculate statistics
    if metrics['rtts']:
        metrics['avg_rtt'] = sum(metrics['rtts']) / len(metrics['rtts'])
        metrics['min_rtt'] = min(metrics['rtts'])
        metrics['max_rtt'] = max(metrics['rtts'])
        
        # Calculate jitter (standard deviation of RTTs)
        mean = metrics['avg_rtt']
        variance = sum((x - mean) ** 2 for x in metrics['rtts']) / len(metrics['rtts'])
        metrics['rtt_jitter'] = variance ** 0.5
        
    # Try to run traceroute to get path information
    try:
        trace_output = src.cmd(f'traceroute -n {dst.IP()}')
        metrics['traceroute'] = trace_output
        
        # Count hops
        hop_count = 0
        for line in trace_output.splitlines():
            if re.match(r'^\s*\d+', line.strip()):
                hop_count += 1
        
        metrics['hop_count'] = hop_count
    except:
        metrics['traceroute'] = "Failed to run traceroute"
        
    return metrics

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

def collect_all_network_metrics(net):
    """Collect comprehensive network metrics for all devices."""
    metrics = {
        'timestamp': time.time(),
        'hosts': {},
        'switches': {},
        'links': {},
        'paths': {},
        'protocol_distribution': {},
        'stability': {},
        'hardware_resources': {}
    }
    
    # Get all hosts and switches - use the name as the key
    hosts = {h.name: h for h in net.hosts}
    switches = {s.name: s for s in net.switches}
    
    # Collect host metrics
    for host_name, host in hosts.items():
        metrics['hosts'][host_name] = {}
        
        # Basic health parameters
        if hasattr(host, 'get_health_parameters'):
            metrics['hosts'][host_name].update(host.get_health_parameters())
        
        # Advanced host metrics
        metrics['hosts'][host_name]['advanced'] = get_advanced_host_metrics(host)
        
        # Protocol distribution
        metrics['protocol_distribution'][host_name] = analyze_protocol_distribution(host)
    
    # Collect switch metrics
    for switch_name, switch in switches.items():
        metrics['switches'][switch_name] = {}
        
        # Basic health parameters
        if hasattr(switch, 'get_health_parameters'):
            metrics['switches'][switch_name].update(switch.get_health_parameters())
        
        # Advanced switch metrics
        metrics['switches'][switch_name]['advanced'] = get_advanced_switch_metrics(switch)
        
        # Hardware resources
        metrics['hardware_resources'][switch_name] = monitor_hardware_resources(switch)
    
    # Collect path metrics between all host pairs
    for src_name, src_host in hosts.items():
        for dst_name, dst_host in hosts.items():
            if src_name != dst_name:
                path_key = f"{src_name}-to-{dst_name}"
                metrics['paths'][path_key] = measure_path_characteristics(net, src_name, dst_name)
                
                # Add advanced path analysis
                metrics['paths'][path_key]['advanced'] = analyze_path_quality(net, src_name, dst_name)
    
    # If we have historical data, analyze stability
    if not hasattr(collect_all_network_metrics, 'metrics_history'):
        collect_all_network_metrics.metrics_history = []
    
    collect_all_network_metrics.metrics_history.append(metrics)
    if len(collect_all_network_metrics.metrics_history) > 10:  # Keep last 10 measurements
        collect_all_network_metrics.metrics_history.pop(0)
    
    if len(collect_all_network_metrics.metrics_history) > 1:
        metrics['stability'] = analyze_long_term_stability(collect_all_network_metrics.metrics_history)
    
    return metrics

def display_network_metrics(metrics):
    """Display comprehensive network metrics in a readable format."""
    print("\n--- Comprehensive Network Metrics ---")
    
    # Display host metrics
    print("\n=== Host Metrics ===")
    for host_name, host_metrics in metrics['hosts'].items():
        print(f"\n  Host: {host_name}")
        
        # Basic CPU and memory
        if 'cpu' in host_metrics and 'usage_percent' in host_metrics['cpu']:
            print(f"    CPU Usage: {host_metrics['cpu']['usage_percent']:.2f}%")
        
        if 'memory' in host_metrics and 'UsedPercent' in host_metrics['memory']:
            print(f"    Memory Usage: {host_metrics['memory']['UsedPercent']:.2f}%")
        
        # Advanced metrics
        if 'advanced' in host_metrics:
            advanced = host_metrics['advanced']
            
            # Load average
            if 'load_average' in advanced:
                print(f"    Load Average: {advanced['load_average'].get('1min', 0):.2f} (1min), "
                      f"{advanced['load_average'].get('5min', 0):.2f} (5min), "
                      f"{advanced['load_average'].get('15min', 0):.2f} (15min)")
            
            # TCP statistics
            if 'tcp_detailed' in advanced:
                tcp = advanced['tcp_detailed']
                print(f"    TCP Connections: {tcp.get('current_established', 0)} established, "
                      f"{tcp.get('active_opens', 0)} active opens, "
                      f"{tcp.get('passive_opens', 0)} passive opens")
        
        # Protocol distribution
        if host_name in metrics['protocol_distribution']:
            proto = metrics['protocol_distribution'][host_name]
            print("    Protocol Distribution:")
            for protocol, percentage in proto.items():
                if 'percentage' in protocol:
                    print(f"      {protocol.replace('_percentage', '')}: {percentage:.1f}%")
    
    # Display switch metrics
    print("\n=== Switch Metrics ===")
    for switch_name, switch_metrics in metrics['switches'].items():
        print(f"\n  Switch: {switch_name}")
        
        # Flow information
        if 'switch' in switch_metrics and 'flow_stats' in switch_metrics['switch']:
            flow_stats = switch_metrics['switch']['flow_stats']
            print(f"    Flow Count: {flow_stats.get('flow_count', 0)}")
            print(f"    Packet Count: {flow_stats.get('packet_count', 0)}")
            print(f"    Byte Count: {flow_stats.get('byte_count', 0)}")
        
        # CPU and memory
        if 'switch' in switch_metrics:
            switch_stats = switch_metrics['switch']
            if 'cpu_utilization' in switch_stats and switch_stats['cpu_utilization']:
                print(f"    CPU Utilization: {switch_stats['cpu_utilization']:.2f}%")
            if 'memory_usage' in switch_stats and switch_stats['memory_usage']:
                print(f"    Memory Usage: {switch_stats['memory_usage']:.2f}%")
        
        # Advanced metrics
        if 'advanced' in switch_metrics:
            advanced = switch_metrics['advanced']
            
            # Drop reasons
            if 'drop_reasons' in advanced:
                drops = advanced['drop_reasons']
                total_drops = sum(drops.values())
                print(f"    Packet Drops: {total_drops} total")
                for reason, count in drops.items():
                    if count > 0:
                        print(f"      {reason}: {count}")
            
            # Control plane
            if 'control_plane' in advanced:
                ctrl = advanced['control_plane']
                print(f"    Control Plane: {ctrl.get('connection_count', 0)} connections, "
                      f"{ctrl.get('pending_requests', 0)} pending requests, "
                      f"{ctrl.get('message_processing_rate', 0)} msgs/sec")
        
        # Hardware resources
        if switch_name in metrics['hardware_resources']:
            hw = metrics['hardware_resources'][switch_name]
            
            # IO wait
            if 'io_wait' in hw:
                print(f"    IO Wait: {hw['io_wait']:.2f}%")
            
            # Memory details
            if 'memory_details' in hw:
                mem = hw['memory_details']
                print(f"    Memory Details: {mem.get('free_chunks', 0)} free chunks, "
                      f"{mem.get('cached', 0)} cached, "
                      f"{mem.get('dirty', 0)} dirty")
    
    # Display path metrics
    print("\n=== Path Metrics ===")
    for path_key, path_metrics in metrics['paths'].items():
        print(f"\n  Path: {path_key}")
        
        # Basic path metrics
        if 'avg_rtt' in path_metrics:
            print(f"    RTT: {path_metrics['avg_rtt']:.2f} ms")
        if 'rtt_jitter' in path_metrics:
            print(f"    Jitter: {path_metrics['rtt_jitter']:.2f} ms")
        
        # Advanced path metrics
        if 'advanced' in path_metrics:
            advanced = path_metrics['advanced']
            
            # Path MTU
            if 'path_mtu' in advanced and advanced['path_mtu']:
                print(f"    Path MTU: {advanced['path_mtu']} bytes")
            
            # Path asymmetry
            if 'path_asymmetry' in advanced and advanced['path_asymmetry'] is not None:
                asymmetry = advanced['path_asymmetry'] * 100
                print(f"    Path Asymmetry: {asymmetry:.1f}%")
            
            # TCP handshake time
            if 'tcp_handshake_time' in advanced and advanced['tcp_handshake_time']:
                print(f"    TCP Handshake Time: {advanced['tcp_handshake_time'] * 1000:.2f} ms")
    
    # Display stability metrics
    if 'stability' in metrics and metrics['stability']:
        print("\n=== Network Stability ===")
        stability = metrics['stability']
        
        # Latency stability
        if 'latency_stability' in stability:
            print(f"  Latency Variability: {stability['latency_stability']:.2f} ms")
        
        # Bandwidth stability
        if 'bandwidth_stability' in stability:
            print(f"  Bandwidth Variability: {stability['bandwidth_stability']:.2f} Mbps")
        
        # Packet loss trend
        if 'packet_loss_trend' in stability:
            trend = stability['packet_loss_trend']
            print(f"  Packet Loss Trend: {trend.get('trend', 'unknown')}, "
                  f"Rate of Change: {trend.get('change_rate', 0):.2f}%")

if __name__ == '__main__':
    # Clean up any previous Mininet runs first
    print("\n--- Cleaning up previous Mininet instances ---")
    cleanup()  # Use the imported cleanup function
    
    setLogLevel('info')
    
    # Use our enhanced topology
    topo = EnhancedTopo()
    net = None
    
    try:
        net = Mininet(topo, host=ExtendedHost, link=TCLink)
        net.start()

        h1, h2 = net.get('h1', 'h2')
        s1 = net.get('s1')

        print("\n--- Measuring Network Parameters ---")

        # Measure latency
        latency = measure_latency(net, 'h1', 'h2')
        if latency is not None:
            print(f"Latency (average): {latency:.2f} ms")
        else:
            print("Could not measure latency.")

        # Detailed TCP performance measurements
        tcp_metrics = measure_tcp_performance(net, 'h1', 'h2')
        if 'avg_bandwidth' in tcp_metrics:
            print(f"TCP Bandwidth (average): {tcp_metrics['avg_bandwidth']:.2f} Mbit/s")
        else:
            print("Could not measure TCP bandwidth.")
            
        # UDP performance with jitter and loss
        udp_metrics = measure_udp_performance(net, 'h1', 'h2', bandwidth='20M')
        if 'avg_bandwidth' in udp_metrics and 'avg_jitter' in udp_metrics:
            print(f"UDP Bandwidth (average): {udp_metrics['avg_bandwidth']:.2f} Mbit/s")
            print(f"UDP Jitter (average): {udp_metrics['avg_jitter']:.2f} ms")
            if udp_metrics['packet_loss'] is not None:
                print(f"UDP Packet Loss: {udp_metrics['packet_loss']:.2f}%")
        else:
            print("Could not measure UDP performance.")

        # Path characteristics
        path_metrics = measure_path_characteristics(net, 'h1', 'h2')
        if 'avg_rtt' in path_metrics and 'rtt_jitter' in path_metrics:
            print(f"Path RTT (average): {path_metrics['avg_rtt']:.2f} ms")
            print(f"Path RTT Jitter: {path_metrics['rtt_jitter']:.2f} ms")
            
        # Uptime (of the Mininet host OS)
        uptime_seconds = get_uptime()
        uptime_minutes = uptime_seconds / 60
        uptime_hours = uptime_minutes / 60
        print(f"Uptime (of Mininet host): {int(uptime_hours)} hours, {int(uptime_minutes % 60)} minutes, {int(uptime_seconds % 60)} seconds")

        # Get flow count
        get_flow_count(net)

        # Start continuous iperf traffic in the background
        info("\n*** Starting continuous iperf traffic from h1 to h2...\n")
        iperf_server_process = h2.popen('iperf -s -p 5001')
        time.sleep(0.5)  # Give server time to start
        # Start continuous traffic for 1 hour with bandwidth of 20Mbps and print interval of 10 seconds
        # Using UDP (-u) to ensure consistent traffic generation
        iperf_client_process = h1.popen('iperf -c %s -p 5001 -t 3600 -b 20M -i 10 -u' % h2.IP())

        # Collect initial comprehensive metrics
        print("\n--- Collecting Initial Comprehensive Network Metrics ---")
        initial_metrics = collect_all_network_metrics(net)
        
        # Display comprehensive metrics
        display_network_metrics(initial_metrics)

        print("\n--- Printing Health Parameters every 5 seconds ---")
        while True:
            print(f"\n--- Health Data at {time.strftime('%Y-%m-%d %H:%M:%S')} ---")
            
            # Collect comprehensive metrics
            current_metrics = collect_all_network_metrics(net)
            
            # Display comprehensive metrics instead of just switch health
            display_network_metrics(current_metrics)
            
            time.sleep(5)

    except KeyboardInterrupt:
        print("\n--- Stopping Health Parameter Monitoring ---")
    except Exception as e:
        print(f"\n--- Error encountered: {e} ---")
        import traceback
        traceback.print_exc()
    finally:
        # Clean up the background iperf processes
        if 'iperf_client_process' in locals():
            iperf_client_process.terminate()
        if 'iperf_server_process' in locals():
            iperf_server_process.terminate()
        if net:
            net.stop()
        cleanup()
