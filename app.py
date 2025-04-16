from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
import os
import glob
import csv
import pandas as pd
import re
from datetime import datetime

app = Flask(__name__)

# Initialize extensions
socketio = SocketIO(app, cors_allowed_origins="*")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/sos")
def sos():
    # Read SOS data from CSV
    sos_data = []
    try:
        with open("network/dc_sos_data.csv", "r") as file:
            csv_reader = csv.DictReader(file)
            for row in csv_reader:
                sos_data.append(row)
    except FileNotFoundError:
        sos_data = [{"error": "SOS data file not found"}]

    # Parse attack log to determine network status
    network_status = parse_attack_log()

    return render_template("sos.html", sos_data=sos_data, network_status=network_status)


def parse_attack_log():
    """Parse attack_log.txt to determine the status of each cluster center"""

    # Default status for each area is "Normal"
    status = {
        "Academic Area": {"status": "normal", "message": ""},
        "Hostel Area": {"status": "normal", "message": ""},
        "Housing Area": {"status": "normal", "message": ""},
    }

    try:
        with open("attack_log.txt", "r") as file:
            log_content = file.read()

            # Check for attacks in CC1 (Academic Area)
            if re.search(r"ATTACK\s+DETECTED\s+AT\s+CC1", log_content, re.IGNORECASE):
                status["Academic Area"]["status"] = "danger"
                # Extract attack type if available
                attack_type_match = re.search(
                    r"CC1\.\s+POSSIBLY\s+([A-Z\s]+)ATTACK", log_content, re.IGNORECASE
                )
                if attack_type_match:
                    attack_type = attack_type_match.group(1).strip()
                    status["Academic Area"][
                        "message"
                    ] = f"Possible {attack_type} attack detected"
                else:
                    status["Academic Area"]["message"] = "Attack detected"

            # Check for attacks in CC2 (Hostel Area)
            if re.search(r"ATTACK\s+DETECTED\s+AT\s+CC2", log_content, re.IGNORECASE):
                status["Hostel Area"]["status"] = "danger"
                # Extract attack type if available
                attack_type_match = re.search(
                    r"CC2\.\s+POSSIBLY\s+([A-Z\s]+)ATTACK", log_content, re.IGNORECASE
                )
                if attack_type_match:
                    attack_type = attack_type_match.group(1).strip()
                    status["Hostel Area"][
                        "message"
                    ] = f"Possible {attack_type} attack detected"
                else:
                    status["Hostel Area"]["message"] = "Attack detected"
            elif re.search(
                r"NO\s+ATTACK\s+DETECTED\s+AT\s+CC2", log_content, re.IGNORECASE
            ):
                status["Hostel Area"]["status"] = "normal"
                status["Hostel Area"]["message"] = "No attack detected"

            # Check for attacks in CC3 (Housing Area)
            if re.search(r"ATTACK\s+DETECTED\s+AT\s+CC3", log_content, re.IGNORECASE):
                status["Housing Area"]["status"] = "danger"
                # Extract attack type if available
                attack_type_match = re.search(
                    r"CC3\.\s+POSSIBLY\s+([A-Z\s]+)ATTACK", log_content, re.IGNORECASE
                )
                if attack_type_match:
                    attack_type = attack_type_match.group(1).strip()
                    status["Housing Area"][
                        "message"
                    ] = f"Possible {attack_type} attack detected"
                else:
                    status["Housing Area"]["message"] = "Attack detected"

    except FileNotFoundError:
        # If log file is not found, use default "Normal" status
        pass

    return status


@app.route("/cluster/<int:cluster_id>")
def cluster(cluster_id):
    cluster_names = {1: "Academic Area", 2: "Hostel Area", 3: "Housing Area"}

    # Get the cluster name or default to "Unknown Area"
    cluster_name = cluster_names.get(cluster_id, "Unknown Area")

    # Set cluster path based on cluster ID
    if cluster_id == 1:
        cluster_prefix = "cc1"
        full_path = "cc1"
    elif cluster_id == 2:
        cluster_prefix = "cc2"
        full_path = "cc2"
    elif cluster_id == 3:
        cluster_prefix = "cc3"
        full_path = "cc3"
    else:
        cluster_prefix = "unknown"
        full_path = "unknown"

    # Dictionary of graph files with the provided naming pattern
    graph_files = {
        "rx_total_packets": f"/static/graphs/network_stats_{full_path}_Total_Rx_Packets.html",
        "rx_avg_packets": f"/static/graphs/network_stats_{full_path}_Average_Rx_Packets.html",
        "rx_min_packets": f"/static/graphs/network_stats_{full_path}_Min_Rx_Packets.html",
        "rx_max_packets": f"/static/graphs/network_stats_{full_path}_Max_Rx_Packets.html",
        "tx_total_packets": f"/static/graphs/network_stats_{full_path}_Total_Tx_Packets.html",
        "tx_avg_packets": f"/static/graphs/network_stats_{full_path}_Average_Tx_Packets.html",
        "tx_min_packets": f"/static/graphs/network_stats_{full_path}_Min_Tx_Packets.html",
        "tx_max_packets": f"/static/graphs/network_stats_{full_path}_Max_Tx_Packets.html",
        "rx_bytes": f"/static/graphs/network_stats_{full_path}_Average_Rx_Bytes.html",
        "tx_bytes": f"/static/graphs/network_stats_{full_path}_Average_Tx_Bytes.html",
        "rx_errors": f"/static/graphs/network_stats_{full_path}_Average_Rx_Errors.html",
        "tx_errors": f"/static/graphs/network_stats_{full_path}_Average_Tx_Errors.html",
        "rx_utilization": f"/static/graphs/network_stats_{full_path}_Average_Rx_Utilization.html",
        "tx_utilization": f"/static/graphs/network_stats_{full_path}_Average_Tx_Utilization.html",
        "buffer_occupancy": f"/static/graphs/network_stats_{full_path}_Average_Buffer_Occupancy.html",
        "throughput": f"/static/graphs/network_stats_{full_path}_Average_Throughput_(Mbps).html",
        "total_bytes": f"/static/graphs/network_stats_{full_path}_Total_Bytes.html",
        "total_errors": f"/static/graphs/network_stats_{full_path}_Total_Errors.html",
        "total_packets": f"/static/graphs/network_stats_{full_path}_Total_Packets.html",
        "latest_timestamp": f"/static/graphs/network_stats_{full_path}_Latest_Timestamp.html",
        "number_of_ports": f"/static/graphs/network_stats_{full_path}_Number_of_Ports.html",
    }

    # For cluster 2 and 3, let's also try an alternative naming pattern if files are not found
    if cluster_id in [2, 3]:
        # Search the static/graphs directory for files matching the cluster prefix
        static_graphs_dir = os.path.join(app.static_folder, "graphs")
        if os.path.exists(static_graphs_dir):
            alternative_files = glob.glob(
                os.path.join(static_graphs_dir, f"network_stats_{cluster_prefix}*")
            )
            if alternative_files:
                # Extract the full path pattern from the first file found
                first_file = os.path.basename(alternative_files[0])
                parts = first_file.split("_")
                if len(parts) > 2:
                    # Extract the part after 'network_stats_' and before the next underscore
                    alt_full_path = "_".join(parts[2:3])

                    # Update graph files dictionary with the alternative path
                    graph_files = {
                        "rx_total_packets": f"/static/graphs/network_stats_{alt_full_path}_Total_Rx_Packets.html",
                        "rx_avg_packets": f"/static/graphs/network_stats_{alt_full_path}_Average_Rx_Packets.html",
                        "rx_min_packets": f"/static/graphs/network_stats_{alt_full_path}_Min_Rx_Packets.html",
                        "rx_max_packets": f"/static/graphs/network_stats_{alt_full_path}_Max_Rx_Packets.html",
                        "tx_total_packets": f"/static/graphs/network_stats_{alt_full_path}_Total_Tx_Packets.html",
                        "tx_avg_packets": f"/static/graphs/network_stats_{alt_full_path}_Average_Tx_Packets.html",
                        "tx_min_packets": f"/static/graphs/network_stats_{alt_full_path}_Min_Tx_Packets.html",
                        "tx_max_packets": f"/static/graphs/network_stats_{alt_full_path}_Max_Tx_Packets.html",
                        "rx_bytes": f"/static/graphs/network_stats_{alt_full_path}_Average_Rx_Bytes.html",
                        "tx_bytes": f"/static/graphs/network_stats_{alt_full_path}_Average_Tx_Bytes.html",
                        "rx_errors": f"/static/graphs/network_stats_{alt_full_path}_Average_Rx_Errors.html",
                        "tx_errors": f"/static/graphs/network_stats_{alt_full_path}_Average_Tx_Errors.html",
                        "rx_utilization": f"/static/graphs/network_stats_{alt_full_path}_Average_Rx_Utilization.html",
                        "tx_utilization": f"/static/graphs/network_stats_{alt_full_path}_Average_Tx_Utilization.html",
                        "buffer_occupancy": f"/static/graphs/network_stats_{alt_full_path}_Average_Buffer_Occupancy.html",
                        "throughput": f"/static/graphs/network_stats_{alt_full_path}_Average_Throughput_(Mbps).html",
                        "total_bytes": f"/static/graphs/network_stats_{alt_full_path}_Total_Bytes.html",
                        "total_errors": f"/static/graphs/network_stats_{alt_full_path}_Total_Errors.html",
                        "total_packets": f"/static/graphs/network_stats_{alt_full_path}_Total_Packets.html",
                        "latest_timestamp": f"/static/graphs/network_stats_{alt_full_path}_Latest_Timestamp.html",
                        "number_of_ports": f"/static/graphs/network_stats_{alt_full_path}_Number_of_Ports.html",
                    }

    # Simulated device information - in production this would come from your backend
    devices = {
        "router": {"mac": "00:11:22:33:44:55", "ip": "192.168.1.1"},
        "switch1": {"mac": "AA:BB:CC:DD:EE:FF", "ip": ""},
        "switch2": {"mac": "11:22:33:44:55:66", "ip": ""},
        "firewall": {"mac": "AA:BB:CC:11:22:33", "ip": "192.168.1.254"},
    }

    # Simulated statistics - in production this would come from your backend
    stats = {
        "total_packets": 12500,
        "total_bytes": 8750000,
        "total_errors": 25,
        "devices_count": 4,
        "prev_devices_count": 4,
        "latest_timestamp": "2025-04-14 15:30:45",
        "oldest_timestamp": "2025-04-14 10:00:00",
    }

    return render_template(
        "cluster.html",
        cluster_id=cluster_id,
        cluster_name=cluster_name,
        graph_files=graph_files,
        devices=devices,
        stats=stats,
    )


@app.route("/firewall/<int:cluster_id>")
def firewall(cluster_id):
    cluster_names = {1: "Academic Area", 2: "Hostel Area", 3: "Housing Area"}

    # Get the cluster name or default to "Unknown Area"
    cluster_name = cluster_names.get(cluster_id, "Unknown Area")

    # Determine cluster prefix based on cluster_id
    cluster_prefix = f"cc{cluster_id}"

    # Read firewall data from CSV files
    firewall_data = []
    firewall_rules = []

    # Define the column headers for firewall data
    firewall_headers = [
        "Cluster",
        "ID",
        "Timestamp",
        "MAC",
        "Number of Interfaces",
        "Latest Timestamp",
        "Oldest Timestamp",
        "Total Packets",
        "Total Bytes",
        "Total Errors",
        "Total Rx Packets",
        "Total Rx Bytes",
        "Total Rx Errors",
        "Total Tx Packets",
        "Total Tx Bytes",
        "Total Tx Errors",
        "Total Rx Utilization",
        "Total Tx Utilization",
        "Total Throughput (Mbps)",
        "Total Buffer Occupancy",
        "Min Rx Packets",
        "Max Rx Packets",
        "Min Rx Bytes",
        "Max Rx Bytes",
        "Min Rx Errors",
        "Max Rx Errors",
        "Min Tx Packets",
        "Max Tx Packets",
        "Min Tx Bytes",
        "Max Tx Bytes",
        "Min Tx Errors",
        "Max Tx Errors",
        "Min Rx Utilization",
        "Max Rx Utilization",
        "Min Tx Utilization",
        "Max Tx Utilization",
        "Min Throughput (Mbps)",
        "Max Throughput (Mbps)",
        "Min Buffer Occupancy",
        "Max Buffer Occupancy",
        "Average Rx Packets",
        "Average Rx Bytes",
        "Average Rx Errors",
        "Average Tx Packets",
        "Average Tx Bytes",
        "Average Tx Errors",
        "Average Rx Utilization",
        "Average Tx Utilization",
        "Average Throughput (Mbps)",
        "Average Buffer Occupancy",
    ]

    try:
        with open("network/dc_fw_data.csv", "r") as file:
            # Read all rows as strings first
            lines = file.readlines()

            # Process each line and filter by cluster prefix
            for line in lines:
                # Check if the line starts with the cluster prefix followed by a comma
                if line.startswith(f"{cluster_prefix},"):
                    # Split the line and create a dict
                    values = line.strip().split(",")

                    # Create a dictionary with defined headers
                    data_dict = {}
                    for i, header in enumerate(firewall_headers):
                        if i < len(values):
                            data_dict[header] = values[i]
                        else:
                            data_dict[header] = ""

                    # Add to firewall data
                    firewall_data.append(data_dict)
    except FileNotFoundError:
        firewall_data = [{"error": f"Firewall data file for {cluster_name} not found"}]

    # Define the column headers for firewall rules
    try:
        with open("network/dc_fw_rules_data.csv", "r") as file:
            # Read all rows as strings first
            lines = file.readlines()

            # Process each line and filter by cluster prefix
            for line in lines:
                # Check if the line starts with the cluster prefix followed by a comma
                if line.startswith(f"{cluster_prefix},"):
                    # Split the line and create a dict
                    values = line.strip().split(",")

                    # Create a simple dict for rules
                    if len(values) > 3:  # Make sure there's enough data
                        firewall_rules.append(
                            {
                                "Cluster": values[0],
                                "ID": values[1],
                                "Timestamp": values[2],
                                "Rule": values[3] if len(values) > 3 else "",
                                # Add other fields as needed
                            }
                        )
    except FileNotFoundError:
        firewall_rules = [
            {"error": f"Firewall rules file for {cluster_name} not found"}
        ]

    return render_template(
        "firewall.html",
        cluster_id=cluster_id,
        cluster_name=cluster_name,
        firewall_data=firewall_data,
        firewall_rules=firewall_rules,
    )


@app.route("/router/<int:cluster_id>")
def router(cluster_id):
    cluster_names = {1: "Academic Area", 2: "Hostel Area", 3: "Housing Area"}

    # Get the cluster name or default to "Unknown Area"
    cluster_name = cluster_names.get(cluster_id, "Unknown Area")

    # Determine cluster prefix based on cluster_id
    cluster_prefix = f"cc{cluster_id}"

    # Define the column headers for router data
    router_headers = [
        "Cluster",
        "ID",
        "Timestamp",
        "MAC",
        "Number of Ports",
        "Latest Timestamp",
        "Oldest Timestamp",
        "Total Packets",
        "Total Bytes",
        "Total Errors",
        "Total Rx Packets",
        "Total Rx Bytes",
        "Total Rx Errors",
        "Total Tx Packets",
        "Total Tx Bytes",
        "Total Tx Errors",
        "Total Rx Utilization",
        "Total Tx Utilization",
        "Total Throughput (Mbps)",
        "Total Buffer Occupancy",
        "Min Rx Packets",
        "Max Rx Packets",
        "Min Rx Bytes",
        "Max Rx Bytes",
        "Min Rx Errors",
        "Max Rx Errors",
        "Min Tx Packets",
        "Max Tx Packets",
        "Min Tx Bytes",
        "Max Tx Bytes",
        "Min Tx Errors",
        "Max Tx Errors",
        "Min Rx Utilization",
        "Max Rx Utilization",
        "Min Tx Utilization",
        "Max Tx Utilization",
        "Min Throughput (Mbps)",
        "Max Throughput (Mbps)",
        "Min Buffer Occupancy",
        "Max Buffer Occupancy",
        "Average Rx Packets",
        "Average Rx Bytes",
        "Average Rx Errors",
        "Average Tx Packets",
        "Average Tx Bytes",
        "Average Tx Errors",
        "Average Rx Utilization",
        "Average Tx Utilization",
        "Average Throughput (Mbps)",
        "Average Buffer Occupancy",
    ]

    # Read router data from CSV files
    router_data = []
    router_rules = []

    try:
        with open("network/dc_rt_data.csv", "r") as file:
            # Read all rows as strings first
            lines = file.readlines()

            # Process each line and filter by cluster prefix
            for line in lines:
                # Check if the line starts with the cluster prefix followed by a comma
                if line.startswith(f"{cluster_prefix},"):
                    # Split the line and create a dict
                    values = line.strip().split(",")

                    # Create a dictionary with defined headers
                    data_dict = {}
                    for i, header in enumerate(router_headers):
                        if i < len(values):
                            data_dict[header] = values[i]
                        else:
                            data_dict[header] = ""

                    # Add to router data
                    router_data.append(data_dict)
    except FileNotFoundError:
        router_data = [{"error": f"Router data file for {cluster_name} not found"}]

    try:
        with open("network/dc_rt_rules_data.csv", "r") as file:
            # Read all rows as strings first
            lines = file.readlines()

            # Process each line and filter by cluster prefix
            for line in lines:
                # Check if the line starts with the cluster prefix followed by a comma
                if line.startswith(f"{cluster_prefix},"):
                    # Split the line and create a dict
                    values = line.strip().split(",")

                    # Create a simple dict for rules
                    if len(values) > 3:  # Make sure there's enough data
                        router_rules.append(
                            {
                                "Cluster": values[0],
                                "ID": values[1],
                                "Timestamp": values[2],
                                "Rule": values[3] if len(values) > 3 else "",
                                # Add other fields as needed
                            }
                        )
    except FileNotFoundError:
        router_rules = [{"error": f"Router rules file for {cluster_name} not found"}]

    return render_template(
        "router.html",
        cluster_id=cluster_id,
        cluster_name=cluster_name,
        router_data=router_data,
        router_rules=router_rules,
    )


if __name__ == "__main__":
    app.run(debug=True)
