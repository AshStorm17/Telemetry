from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
import os
import glob
import csv
import pandas as pd
import re

app = Flask(__name__)

# Initialize extensions
socketio = SocketIO(app, cors_allowed_origins="*")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/sos')
def sos():
    # Read SOS data from CSV
    sos_data = []
    try:
        with open('network/dc_sos_data.csv', 'r') as file:
            csv_reader = csv.DictReader(file)
            for row in csv_reader:
                sos_data.append(row)
    except FileNotFoundError:
        sos_data = [{"error": "SOS data file not found"}]
    
    # Parse attack log to determine network status
    network_status = parse_attack_log()
    
    return render_template('sos.html', sos_data=sos_data, network_status=network_status)

def parse_attack_log():
    """Parse attack_log.txt to determine the status of each cluster center"""
    
    # Default status for each area is "Normal"
    status = {
        "Academic Area": {"status": "normal", "message": ""},
        "Hostel Area": {"status": "normal", "message": ""},
        "Housing Area": {"status": "normal", "message": ""}
    }
    
    try:
        with open('attack_log.txt', 'r') as file:
            log_content = file.read()
            
            # Check for attacks in CC1 (Academic Area)
            if re.search(r'ATTACK\s+DETECTED\s+AT\s+CC1', log_content, re.IGNORECASE):
                status["Academic Area"]["status"] = "danger"
                # Extract attack type if available
                attack_type_match = re.search(r'CC1\.\s+POSSIBLY\s+([A-Z\s]+)ATTACK', log_content, re.IGNORECASE)
                if attack_type_match:
                    attack_type = attack_type_match.group(1).strip()
                    status["Academic Area"]["message"] = f"Possible {attack_type} attack detected"
                else:
                    status["Academic Area"]["message"] = "Attack detected"
            
            # Check for attacks in CC2 (Hostel Area)
            if re.search(r'ATTACK\s+DETECTED\s+AT\s+CC2', log_content, re.IGNORECASE):
                status["Hostel Area"]["status"] = "danger"
                # Extract attack type if available
                attack_type_match = re.search(r'CC2\.\s+POSSIBLY\s+([A-Z\s]+)ATTACK', log_content, re.IGNORECASE)
                if attack_type_match:
                    attack_type = attack_type_match.group(1).strip()
                    status["Hostel Area"]["message"] = f"Possible {attack_type} attack detected"
                else:
                    status["Hostel Area"]["message"] = "Attack detected"
            elif re.search(r'NO\s+ATTACK\s+DETECTED\s+AT\s+CC2', log_content, re.IGNORECASE):
                status["Hostel Area"]["status"] = "normal"
                status["Hostel Area"]["message"] = "No attack detected"
            
            # Check for attacks in CC3 (Housing Area)
            if re.search(r'ATTACK\s+DETECTED\s+AT\s+CC3', log_content, re.IGNORECASE):
                status["Housing Area"]["status"] = "danger"
                # Extract attack type if available
                attack_type_match = re.search(r'CC3\.\s+POSSIBLY\s+([A-Z\s]+)ATTACK', log_content, re.IGNORECASE)
                if attack_type_match:
                    attack_type = attack_type_match.group(1).strip()
                    status["Housing Area"]["message"] = f"Possible {attack_type} attack detected"
                else:
                    status["Housing Area"]["message"] = "Attack detected"
            
    except FileNotFoundError:
        # If log file is not found, use default "Normal" status
        pass
    
    return status

@app.route('/cluster/<int:cluster_id>')
def cluster(cluster_id):
    cluster_names = {
        1: "Academic Area",
        2: "Hostel Area",
        3: "Housing Area"
    }
    
    # Get the cluster name or default to "Unknown Area"
    cluster_name = cluster_names.get(cluster_id, "Unknown Area")
    
    # Set cluster path based on cluster ID
    if cluster_id == 1:
        cluster_prefix = "1e-97"
        full_path = "1e-97-ec-b3-cc-5f"
    elif cluster_id == 2:
        cluster_prefix = "2e-bc"
        full_path = "2e-bc-ec-b3-cc-5f"
    elif cluster_id == 3:
        cluster_prefix = "3e-ad"
        full_path = "3e-ad-ec-b3-cc-5f"
    else:
        cluster_prefix = "unknown"
        full_path = "unknown"
    
    # Dictionary of graph files with the provided naming pattern
    graph_files = {
        'rx_total_packets': f'/static/graphs/network_stats_{full_path}_Total_Rx_Packets.html',
        'rx_avg_packets': f'/static/graphs/network_stats_{full_path}_Average_Rx_Packets.html',
        'rx_min_packets': f'/static/graphs/network_stats_{full_path}_Min_Rx_Packets.html',
        'rx_max_packets': f'/static/graphs/network_stats_{full_path}_Max_Rx_Packets.html',
        'tx_total_packets': f'/static/graphs/network_stats_{full_path}_Total_Tx_Packets.html',
        'tx_avg_packets': f'/static/graphs/network_stats_{full_path}_Average_Tx_Packets.html',
        'tx_min_packets': f'/static/graphs/network_stats_{full_path}_Min_Tx_Packets.html',
        'tx_max_packets': f'/static/graphs/network_stats_{full_path}_Max_Tx_Packets.html',
        'rx_bytes': f'/static/graphs/network_stats_{full_path}_Average_Rx_Bytes.html',
        'tx_bytes': f'/static/graphs/network_stats_{full_path}_Average_Tx_Bytes.html',
        'rx_errors': f'/static/graphs/network_stats_{full_path}_Average_Rx_Errors.html',
        'tx_errors': f'/static/graphs/network_stats_{full_path}_Average_Tx_Errors.html',
        'rx_utilization': f'/static/graphs/network_stats_{full_path}_Average_Rx_Utilization.html',
        'tx_utilization': f'/static/graphs/network_stats_{full_path}_Average_Tx_Utilization.html',
        'buffer_occupancy': f'/static/graphs/network_stats_{full_path}_Average_Buffer_Occupancy.html',
        'throughput': f'/static/graphs/network_stats_{full_path}_Average_Throughput_(Mbps).html',
        'total_bytes': f'/static/graphs/network_stats_{full_path}_Total_Bytes.html',
        'total_errors': f'/static/graphs/network_stats_{full_path}_Total_Errors.html',
        'total_packets': f'/static/graphs/network_stats_{full_path}_Total_Packets.html',
        'latest_timestamp': f'/static/graphs/network_stats_{full_path}_Latest_Timestamp.html',
        'number_of_ports': f'/static/graphs/network_stats_{full_path}_Number_of_Ports.html'
    }
    
    # For cluster 2 and 3, let's also try an alternative naming pattern if files are not found
    if cluster_id in [2, 3]:
        # Search the static/graphs directory for files matching the cluster prefix
        static_graphs_dir = os.path.join(app.static_folder, 'graphs')
        if os.path.exists(static_graphs_dir):
            alternative_files = glob.glob(os.path.join(static_graphs_dir, f'network_stats_{cluster_prefix}*'))
            if alternative_files:
                # Extract the full path pattern from the first file found
                first_file = os.path.basename(alternative_files[0])
                parts = first_file.split('_')
                if len(parts) > 2:
                    # Extract the part after 'network_stats_' and before the next underscore
                    alt_full_path = '_'.join(parts[1:3])
                    
                    # Update graph files dictionary with the alternative path
                    graph_files = {
                        'rx_total_packets': f'/static/graphs/network_stats_{alt_full_path}_Total_Rx_Packets.html',
                        'rx_avg_packets': f'/static/graphs/network_stats_{alt_full_path}_Average_Rx_Packets.html',
                        'rx_min_packets': f'/static/graphs/network_stats_{alt_full_path}_Min_Rx_Packets.html',
                        'rx_max_packets': f'/static/graphs/network_stats_{alt_full_path}_Max_Rx_Packets.html',
                        'tx_total_packets': f'/static/graphs/network_stats_{alt_full_path}_Total_Tx_Packets.html',
                        'tx_avg_packets': f'/static/graphs/network_stats_{alt_full_path}_Average_Tx_Packets.html',
                        'tx_min_packets': f'/static/graphs/network_stats_{alt_full_path}_Min_Tx_Packets.html',
                        'tx_max_packets': f'/static/graphs/network_stats_{alt_full_path}_Max_Tx_Packets.html',
                        'rx_bytes': f'/static/graphs/network_stats_{alt_full_path}_Average_Rx_Bytes.html',
                        'tx_bytes': f'/static/graphs/network_stats_{alt_full_path}_Average_Tx_Bytes.html',
                        'rx_errors': f'/static/graphs/network_stats_{alt_full_path}_Average_Rx_Errors.html',
                        'tx_errors': f'/static/graphs/network_stats_{alt_full_path}_Average_Tx_Errors.html',
                        'rx_utilization': f'/static/graphs/network_stats_{alt_full_path}_Average_Rx_Utilization.html',
                        'tx_utilization': f'/static/graphs/network_stats_{alt_full_path}_Average_Tx_Utilization.html',
                        'buffer_occupancy': f'/static/graphs/network_stats_{alt_full_path}_Average_Buffer_Occupancy.html',
                        'throughput': f'/static/graphs/network_stats_{alt_full_path}_Average_Throughput_(Mbps).html',
                        'total_bytes': f'/static/graphs/network_stats_{alt_full_path}_Total_Bytes.html',
                        'total_errors': f'/static/graphs/network_stats_{alt_full_path}_Total_Errors.html',
                        'total_packets': f'/static/graphs/network_stats_{alt_full_path}_Total_Packets.html',
                        'latest_timestamp': f'/static/graphs/network_stats_{alt_full_path}_Latest_Timestamp.html',
                        'number_of_ports': f'/static/graphs/network_stats_{alt_full_path}_Number_of_Ports.html'
                    }
    
    # Simulated device information - in production this would come from your backend
    devices = {
        "router": {"mac": "00:11:22:33:44:55", "ip": "192.168.1.1"},
        "switch1": {"mac": "AA:BB:CC:DD:EE:FF", "ip": ""},
        "switch2": {"mac": "11:22:33:44:55:66", "ip": ""},
        "firewall": {"mac": "AA:BB:CC:11:22:33", "ip": "192.168.1.254"}
    }
    
    # Simulated statistics - in production this would come from your backend
    stats = {
        "total_packets": 12500,
        "total_bytes": 8750000,
        "total_errors": 25,
        "devices_count": 4,
        "prev_devices_count": 4,
        "latest_timestamp": "2025-04-14 15:30:45",
        "oldest_timestamp": "2025-04-14 10:00:00"
    }
    
    return render_template(
        'cluster.html',
        cluster_id=cluster_id,
        cluster_name=cluster_name,
        graph_files=graph_files,
        devices=devices,
        stats=stats
    )

@app.route('/firewall/<int:cluster_id>')
def firewall(cluster_id):
    cluster_names = {
        1: "Academic Area",
        2: "Hostel Area",
        3: "Housing Area"
    }
    
    # Get the cluster name or default to "Unknown Area"
    cluster_name = cluster_names.get(cluster_id, "Unknown Area")
    
    # Read firewall data from CSV
    firewall_data = []
    try:
        with open('network/dc_firewall_data.csv', 'r') as file:
            csv_reader = csv.DictReader(file)
            for row in csv_reader:
                firewall_data.append(row)
    except FileNotFoundError:
        firewall_data = [{"error": "Firewall data file not found"}]
    
    return render_template(
        'firewall.html',
        cluster_id=cluster_id,
        cluster_name=cluster_name,
        firewall_data=firewall_data
    )

@app.route('/router/<int:cluster_id>')
def router(cluster_id):
    cluster_names = {
        1: "Academic Area",
        2: "Hostel Area",
        3: "Housing Area"
    }
    
    # Get the cluster name or default to "Unknown Area"
    cluster_name = cluster_names.get(cluster_id, "Unknown Area")
    
    # Read router data from CSV files
    router_data = []
    router_rules = []
    dc_data = []
    
    try:
        with open('network/dc_routers_data.csv', 'r') as file:
            csv_reader = csv.DictReader(file)
            for row in csv_reader:
                router_data.append(row)
    except FileNotFoundError:
        router_data = [{"error": "Router data file not found"}]
        
    try:
        with open('network/dc_routers_rules.csv', 'r') as file:
            csv_reader = csv.DictReader(file)
            for row in csv_reader:
                router_rules.append(row)
    except FileNotFoundError:
        router_rules = [{"error": "Router rules file not found"}]
        
    try:
        with open('network/dc_data.csv', 'r') as file:
            csv_reader = csv.DictReader(file)
            for row in csv_reader:
                dc_data.append(row)
    except FileNotFoundError:
        dc_data = [{"error": "DC data file not found"}]
    
    return render_template(
        'router.html',
        cluster_id=cluster_id,
        cluster_name=cluster_name,
        router_data=router_data,
        router_rules=router_rules,
        dc_data=dc_data
    )

if __name__ == '__main__':
    app.run(debug=True)
    
