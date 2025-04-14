from flask import Flask, render_template, jsonify, send_from_directory
from flask_socketio import SocketIO
import os
import glob

app = Flask(__name__)

# Initialize extensions
socketio = SocketIO(app, cors_allowed_origins="*")

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/sos")
def sos():
    return render_template("sos.html")


@app.route("/cluster/<int:cluster_id>")
def cluster(cluster_id):
    cluster_names = {1: "Academic Area", 2: "Hostel Area", 3: "Housing Area"}

    # Get the cluster name or default to "Unknown Area"
    cluster_name = cluster_names.get(cluster_id, "Unknown Area")

    # Base path prefix based on cluster ID
    prefix = ""
    if cluster_id == 1:
        prefix = "1e-97"
    elif cluster_id == 2:
        prefix = "2e-bc"
    elif cluster_id == 3:
        prefix = "3e-ad"

    # Full path with all subdirectories
    full_path = f"{prefix}-ec-b3-cc-5f"

    # Dictionary of graph files with new naming pattern - match exactly what's on the server
    graph_files = {
        "rx_total_packets": f"static/graphs/network_stats_{full_path}_Total_Rx_Packets.html",
        "rx_avg_packets": f"static/graphs/network_stats_{full_path}_Average_Rx_Packets.html",
        "rx_min_packets": f"static/graphs/network_stats_{full_path}_Min_Rx_Packets.html",
        "rx_max_packets": f"static/graphs/network_stats_{full_path}_Max_Rx_Packets.html",
        "tx_total_packets": f"static/graphs/network_stats_{full_path}_Total_Tx_Packets.html",
        "tx_avg_packets": f"static/graphs/network_stats_{full_path}_Average_Tx_Packets.html",
        "tx_min_packets": f"static/graphs/network_stats_{full_path}_Min_Tx_Packets.html",
        "tx_max_packets": f"static/graphs/network_stats_{full_path}_Max_Tx_Packets.html",
        "rx_bytes": f"static/graphs/network_stats_{full_path}_Average_Rx_Bytes.html",
        "tx_bytes": f"static/graphs/network_stats_{full_path}_Average_Tx_Bytes.html",
        "rx_errors": f"static/graphs/network_stats_{full_path}_Average_Rx_Errors.html",
        "tx_errors": f"static/graphs/network_stats_{full_path}_Average_Tx_Errors.html",
        "rx_utilization": f"static/graphs/network_stats_{full_path}_Rx_Utilization.html",
        "tx_utilization": f"static/graphs/network_stats_{full_path}_Tx_Utilization.html",
        "buffer_occupancy": f"static/graphs/network_stats_{full_path}_Buffer_Occupancy.html",
        "throughput": f"static/graphs/network_stats_{full_path}_Throughput_(Mbps).html",
        "total_bytes": f"static/graphs/network_stats_{full_path}_Total_Bytes.html",
        "total_errors": f"static/graphs/network_stats_{full_path}_Total_Errors.html",
        "total_packets": f"static/graphs/network_stats_{full_path}_Total_Packets.html",
        "latest_timestamp": f"static/graphs/network_stats_{full_path}_Latest_Timestamp.html",
        "number_of_ports": f"static/graphs/network_stats_{full_path}_Number_of_Ports.html",
    }

    # Check if graph files exist and generate placeholders if they don't
    static_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
    graphs_folder = os.path.join(static_folder, "graphs")

    # Create the graphs directory if it doesn't exist
    os.makedirs(graphs_folder, exist_ok=True)

    # Check for each graph file and create placeholders if needed
    for key, path in graph_files.items():
        full_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), path)
        dir_path = os.path.dirname(full_file_path)

        # Create directory if it doesn't exist
        os.makedirs(dir_path, exist_ok=True)

        # Create placeholder HTML file if it doesn't exist
        if not os.path.exists(full_file_path):
            with open(full_file_path, "w") as f:
                f.write(
                    f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Graph: {key}</title>
                    <style>
                        body {{
                            font-family: Arial, sans-serif;
                            display: flex;
                            justify-content: center;
                            align-items: center;
                            height: 100vh;
                            margin: 0;
                            background-color: #f8f9fa;
                            color: #333;
                        }}
                        .placeholder {{
                            text-align: center;
                            padding: 20px;
                        }}
                        .placeholder svg {{
                            max-width: 100%;
                            height: auto;
                        }}
                        @media (prefers-color-scheme: dark) {{
                            body {{
                                background-color: #121212;
                                color: #e0e0e0;
                            }}
                        }}
                    </style>
                </head>
                <body>
                    <div class="placeholder">
                        <svg width="400" height="200" viewBox="0 0 400 200">
                            <!-- Grid lines -->
                            <line x1="50" y1="150" x2="350" y2="150" stroke="#ccc" stroke-width="1" />
                            <line x1="50" y1="50" x2="50" y2="150" stroke="#ccc" stroke-width="1" />
                            
                            <!-- Sample data line -->
                            <path d="M50,120 C100,140 150,80 200,90 C250,100 300,70 350,100" 
                                  fill="none" stroke="#4a90e2" stroke-width="2" />
                            
                            <!-- X and Y axis labels -->
                            <text x="200" y="180" text-anchor="middle" fill="#777">Time</text>
                            <text x="30" y="100" text-anchor="middle" fill="#777" transform="rotate(-90, 30, 100)">Value</text>
                            
                            <!-- Title -->
                            <text x="200" y="30" text-anchor="middle" fill="#333" font-weight="bold">
                                Sample {key.replace('_', ' ').title()} Data
                            </text>
                        </svg>
                        <p>Generating data visualization...</p>
                    </div>
                </body>
                </html>
                """
                )

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

    return render_template(
        "firewall.html", cluster_id=cluster_id, cluster_name=cluster_name
    )


# Route to serve graph placeholder files directly
@app.route("/graphs/<path:filename>")
def serve_graph(filename):
    return send_from_directory("static/graphs", filename)


if __name__ == "__main__":
    app.run(debug=True)
