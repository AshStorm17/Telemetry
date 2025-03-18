# advanced_metrics.py
import re
import time

def get_advanced_switch_metrics(switch):
    """Collect advanced switch metrics."""
    metrics = {}
    
    # Packet drops and errors by type
    metrics['drop_reasons'] = {
        'ttl_expired': parse_int(switch.cmd("ovs-ofctl dump-flows " + switch.name + " | grep 'reason=invalid_ttl' | wc -l")),
        'no_match': parse_int(switch.cmd("ovs-ofctl dump-flows " + switch.name + " | grep 'reason=no_match' | wc -l")),
        'table_miss': parse_int(switch.cmd("ovs-ofctl dump-flows " + switch.name + " | grep 'table=0, n_packets=0' | wc -l"))
    }
    
    # Control plane metrics
    metrics['control_plane'] = {
        'connection_count': parse_int(switch.cmd("ovs-vsctl list controller | grep is_connected=true | wc -l")),
        'pending_requests': parse_int(switch.cmd("ovs-vsctl list controller | grep 'pending_req' | grep -o '[0-9]*'")),
        'message_processing_rate': get_message_rate(switch)
    }
    
    # Hardware offload information (if supported)
    metrics['hardware_offload'] = check_hardware_offload(switch)
    
    return metrics

def get_advanced_host_metrics(host):
    """Collect advanced host metrics for deeper system analysis."""
    metrics = {}
    
    # Interrupt statistics
    interrupts_output = host.cmd("cat /proc/interrupts")
    metrics['interrupts'] = {
        'total': len(interrupts_output.strip().split('\n')),
        'network_related': count_network_interrupts(interrupts_output)
    }
    
    # Load average (1min, 5min, 15min)
    load_output = host.cmd("cat /proc/loadavg")
    load_parts = load_output.split()
    if len(load_parts) >= 3:
        metrics['load_average'] = {
            '1min': float(load_parts[0]),
            '5min': float(load_parts[1]),
            '15min': float(load_parts[2])
        }
    
    # Context switches and process creation
    vmstat = host.cmd("cat /proc/stat | grep ctxt")
    if "ctxt" in vmstat:
        metrics['context_switches'] = int(vmstat.split()[1])
    
    # Memory fragmentation
    metrics['memory_fragmentation'] = analyze_memory_fragmentation(host)
    
    # Detailed TCP statistics
    metrics['tcp_detailed'] = {
        'active_opens': get_tcp_stat(host, 'ActiveOpens'),
        'passive_opens': get_tcp_stat(host, 'PassiveOpens'),
        'attempt_fails': get_tcp_stat(host, 'AttemptFails'),
        'establish_resets': get_tcp_stat(host, 'EstabResets'),
        'current_established': get_tcp_stat(host, 'CurrEstab')
    }
    
    return metrics

def analyze_path_quality(net, src, dst):
    """In-depth path quality analysis."""
    metrics = {}
    src_host = net.get(src)
    dst_host = net.get(dst)
    
    # Path MTU discovery
    mtu_output = src_host.cmd(f"tracepath {dst_host.IP()}")
    metrics['path_mtu'] = extract_mtu(mtu_output)
    
    # Check for asymmetric routing
    metrics['path_asymmetry'] = check_path_asymmetry(net, src, dst)
    
    # TCP handshake time
    metrics['tcp_handshake_time'] = measure_tcp_handshake_time(src_host, dst_host)
    
    # Bandwidth-delay product (if available)
    if 'bandwidth' in metrics and metrics.get('path_rtt'):
        metrics['bandwidth_delay_product'] = (metrics['path_rtt'] / 1000) * (metrics['bandwidth'] * 125000)
    
    return metrics

def analyze_protocol_distribution(host):
    """Analyze protocol distribution in traffic."""
    metrics = {}
    
    # Run tcpdump for a short time and analyze protocol distribution
    tcpdump_output = host.cmd("timeout 3 tcpdump -nn -c 200 2>/dev/null | grep -v 'listening'")
    packets = tcpdump_output.strip().split('\n')
    
    # Count protocols
    protocol_count = {
        'tcp': 0,
        'udp': 0,
        'icmp': 0,
        'arp': 0,
        'ipv6': 0,
        'other': 0
    }
    
    for packet in packets:
        if "TCP" in packet or "tcp" in packet:
            protocol_count['tcp'] += 1
        elif "UDP" in packet or "udp" in packet:
            protocol_count['udp'] += 1
        elif "ICMP" in packet or "icmp" in packet:
            protocol_count['icmp'] += 1
        elif "ARP" in packet or "arp" in packet:
            protocol_count['arp'] += 1
        elif "IPv6" in packet or "ipv6" in packet:
            protocol_count['ipv6'] += 1
        else:
            protocol_count['other'] += 1
    
    # Calculate percentages
    total = sum(protocol_count.values())
    if total > 0:
        for protocol in protocol_count:
            metrics[f'{protocol}_percentage'] = (protocol_count[protocol] / total) * 100
    
    return metrics

def monitor_hardware_resources(switch):
    """Monitor hardware resources in the switch."""
    metrics = {}
    
    # CPU core utilization
    top_output = switch.cmd("top -bn1 | grep Cpu")
    metrics['cpu_per_core'] = parse_cpu_per_core(top_output)
    
    # Memory allocation details
    metrics['memory_details'] = {
        'free_chunks': parse_int(switch.cmd("cat /proc/meminfo | grep MemFree")),
        'cached': parse_int(switch.cmd("cat /proc/meminfo | grep Cached")),
        'dirty': parse_int(switch.cmd("cat /proc/meminfo | grep Dirty")),
        'writeback': parse_int(switch.cmd("cat /proc/meminfo | grep Writeback"))
    }
    
    # I/O wait time
    iostat = switch.cmd("iostat -c | tail -n 2")
    metrics['io_wait'] = parse_io_wait(iostat)
    
    return metrics

def analyze_long_term_stability(metrics_history):
    """Analyze the stability metrics series for trends and issues."""
    stability = {}
    
    # Extract key metrics from history
    latencies = []
    bandwidths = []
    packet_losses = []
    error_counts = []
    
    for metrics in metrics_history:
        # Extract latency data
        for path_key, path_data in metrics.get('paths', {}).items():
            if 'avg_rtt' in path_data:
                latencies.append(path_data['avg_rtt'])
        
        # Extract bandwidth data
        for path_key, path_data in metrics.get('paths', {}).items():
            if 'bandwidth' in path_data:
                bandwidths.append(path_data['bandwidth'])
        
        # Extract packet loss data
        for path_key, path_data in metrics.get('paths', {}).items():
            if 'packet_loss' in path_data:
                packet_losses.append(path_data['packet_loss'])
        
        # Extract error counts
        error_counts.append(sum_all_errors(metrics))
    
    # Calculate stability metrics
    if latencies:
        stability['latency_stability'] = calculate_std_dev(latencies)
    
    if bandwidths:
        stability['bandwidth_stability'] = calculate_std_dev(bandwidths)
    
    if packet_losses:
        stability['packet_loss_trend'] = analyze_trend(packet_losses)
    
    if error_counts:
        stability['error_count_trend'] = analyze_trend(error_counts)
    
    # Detect recurring patterns
    stability['periodic_patterns'] = detect_periodic_patterns(metrics_history)
    
    # Look for correlation between metrics
    stability['correlations'] = find_metric_correlations(metrics_history)
    
    return stability

# Import helper functions from the main file
from DataExtractor import (
    parse_int, get_message_rate, check_hardware_offload, count_network_interrupts,
    analyze_memory_fragmentation, get_tcp_stat, extract_mtu, check_path_asymmetry,
    measure_tcp_handshake_time, calculate_std_dev, analyze_trend, sum_all_errors,
    detect_periodic_patterns, find_metric_correlations, parse_cpu_per_core, parse_io_wait
)
