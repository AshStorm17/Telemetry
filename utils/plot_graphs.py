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

def generate_graph(data, filename_prefix="network_stats"):
    """
    Generate graphs for each MAC and each parameter using parsed CSV data.
    """
    base_path = '../static/graphs'
    os.makedirs(base_path, exist_ok=True)

    results = {}

    for packet in data:
        timestamp = packet['Timestamp']
        for mac, stats in packet['Stats'].items():
            for parameter_name, value in stats.items():
                # Initialize graph data for each MAC and parameter if not already done
                if (mac, parameter_name) not in results:
                    results[(mac, parameter_name)] = {
                        'x_vals': [],
                        'y_vals': []
                    }

                # Append timestamp and value to the graph data
                results[(mac, parameter_name)]['x_vals'].append(timestamp)
                results[(mac, parameter_name)]['y_vals'].append(float(value) if value.replace('.', '', 1).isdigit() else 0.0)

    # Generate graphs for each MAC and parameter
    graph_paths = {}
    for (mac, parameter_name), graph_data in results.items():
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=graph_data['x_vals'],
            y=graph_data['y_vals'],
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

        graph_paths[f"{mac}_{parameter_name}"] = {
            'html': html_path,
            'png': png_path
        }

    return graph_paths

    
if __name__ == "__main__":
    with app.app_context():
        filename = '../network/dc_data.csv'
        try:
            # Parse the CSV file
            packets = parse_csv(filename)

            # Generate graphs
            results = generate_graph(packets, filename_prefix="network_stats")
            for key, paths in results.items():
                print(f"Generated {key} graphs:")
                print(f" → HTML: {paths['html']}")
                print(f" → PNG : {paths['png']}")

        except Exception as e:
            print(f"Error: {e}")
