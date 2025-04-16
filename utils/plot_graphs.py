import plotly.graph_objects as go
import os
from utils.packet_parser import parse_csv

import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import session
from app import app
from models import db
from models.telemetry import TelemetryData

def generate_live_graphs(session, filename_prefix="network_stats"):
    """
    Generate live graphs for each MAC and each parameter.
    """
    base_path = '../static/graphs'
    os.makedirs(base_path, exist_ok=True)

    # Query distinct MAC addresses and parameters
    mac_addresses = session.query(TelemetryData.mac).distinct().all()
    parameters = session.query(TelemetryData.parameter_name).distinct().all()

    results = {}

    for mac_tuple in mac_addresses:
        mac = mac_tuple[0]
        for param_tuple in parameters:
            parameter_name = param_tuple[0]

            # Query data for the specific MAC and parameter
            data = session.query(TelemetryData).filter_by(mac=mac, parameter_name=parameter_name).order_by(TelemetryData.timestamp).all()

            if not data:
                continue

            x_vals = [entry.timestamp for entry in data]
            y_vals = [entry.value for entry in data]

            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=x_vals,
                y=y_vals,
                mode='lines+markers',
                name=f"{mac} - {parameter_name}"
            ))

            fig.update_layout(
                title=f"{parameter_name} over Time for {mac}",
                xaxis_title="Timestamp",
                yaxis_title=parameter_name
            )

            html_path = os.path.join(base_path, f"{filename_prefix}_{mac.replace(':', '-')}_{parameter_name.replace(' ', '_')}.html")
            png_path = os.path.join(base_path, f"{filename_prefix}_{mac.replace(':', '-')}_{parameter_name.replace(' ', '_')}.png")

            fig.write_html(html_path)
            fig.write_image(png_path)  # Requires `kaleido`

            results[f"{mac}_{parameter_name}"] = {
                'html': html_path,
                'png': png_path
            }

    return results

def generate_graph(file, filename_prefix="network_stats"):
    """
    Generate graphs for each CC name and each parameter using parsed CSV data.
    """
    base_path = '../static/graphs'
    os.makedirs(base_path, exist_ok=True)

    with app.app_context():
        data = parse_csv(file)
    
    results = {}

    for packet in data:
        timestamp = packet['Timestamp']
        cc_name = packet['CC_Name']  # Use CC_Name from the packet
        if not cc_name:
            continue

        # Initialize graph data for the CC name if not already done
        if cc_name not in results:
            results[cc_name] = {}

        for mac, stats in packet['Stats'].items():
            for parameter_name, value in stats.items():
                # Initialize parameter data if not already done
                if parameter_name not in results[cc_name]:
                    results[cc_name][parameter_name] = {
                        'x_vals': [],
                        'y_vals': []
                    }

                # Append timestamp and value to the graph data
                results[cc_name][parameter_name]['x_vals'].append(timestamp)
                results[cc_name][parameter_name]['y_vals'].append(float(value) if value.replace('.', '', 1).isdigit() else 0.0)

    # Generate graphs for each CC name and parameter
    graph_paths = {}
    for cc_name, parameters in results.items():
        for parameter_name, graph_data in parameters.items():
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=graph_data['x_vals'],
                y=graph_data['y_vals'],
                mode='lines+markers',
                name=f"{cc_name} - {parameter_name}"
            ))

            fig.update_layout(
                title=f"{parameter_name} over Time for {cc_name}",
                xaxis_title="Timestamp",
                yaxis_title=parameter_name
            )

            # Update filename to use cc_name instead of mac
            html_path = os.path.join(base_path, f"{filename_prefix}_{cc_name.replace(':', '-')}_{parameter_name.replace(' ', '_')}.html")
            png_path = os.path.join(base_path, f"{filename_prefix}_{cc_name.replace(':', '-')}_{parameter_name.replace(' ', '_')}.png")

            fig.write_html(html_path)
            fig.write_image(png_path)  # Requires `kaleido`

            if cc_name not in graph_paths:
                graph_paths[cc_name] = {}
            graph_paths[cc_name][parameter_name] = {
                'html': html_path,
                'png': png_path
            }

    return graph_paths
    
if __name__ == "__main__":
    with app.app_context():
        filename = '../network/dc_data.csv'
        try:
            results = generate_graph(filename, filename_prefix="network_stats")
            for cc_name, parameters in results.items():
                print(f"Generated graphs for {cc_name}:")
                for parameter_name, paths in parameters.items():
                    print(f" → Parameter: {parameter_name}")
                    print(f"   → HTML: {paths['html']}")
                    print(f"   → PNG : {paths['png']}")

        except Exception as e:
            print(f"Error: {e}")
