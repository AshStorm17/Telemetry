import plotly.graph_objects as go
import os
from utils.packet_parser import parse_csv

def generate_graph(data, filename_prefix, parameter_name):
    x_vals = []
    y_vals = []

    for packet in data:
        timestamp = packet['Timestamp']
        for mac, stats in packet['Stats'].items():
            if parameter_name in stats:
                x_vals.append(timestamp)
                y_vals.append(float(stats[parameter_name]))

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=x_vals,
        y=y_vals,
        mode='lines+markers',
        name=parameter_name
    ))

    fig.update_layout(
        title=f"{parameter_name} over Time",
        xaxis_title="Timestamp",
        yaxis_title=parameter_name
    )

    base_path = '../static/graphs'
    os.makedirs(base_path, exist_ok=True)

    html_path = os.path.join(base_path, f"{filename_prefix}_{parameter_name.replace(' ', '_')}.html")
    png_path = os.path.join(base_path, f"{filename_prefix}_{parameter_name.replace(' ', '_')}.png")

    fig.write_html(html_path)
    fig.write_image(png_path)  # Requires `kaleido`

    return {
        'html': html_path,
        'png': png_path
    }

def generate_all_graphs(csv_path, filename_prefix="network_stats"):
    try:
        packets = parse_csv(csv_path)
        parameters = [
            'Total Packets',
            'Total Bytes',
            'Average Rx Utilization',
            'Average Tx Utilization',
            'Total Errors',
            'Average Throughput (Mbps)',
            'Max Tx Bytes'
        ]

        results = {}
        for param in parameters:
            results[param] = generate_graph(packets, filename_prefix, param)
        return results
    except Exception as e:
        print(f"Error generating graphs: {e}")
        return {}
    
if __name__ == "__main__":
    # Run this when graph_utils.py is executed directly
    filename = '../network/dc_data.csv'
    try:
        all_packets = parse_csv(filename)

        parameters = [
            'Total Packets',
            'Total Bytes',
            'Average Rx Utilization',
            'Average Tx Utilization',
            'Total Errors',
            'Average Throughput (Mbps)',
            'Max Tx Bytes'
        ]

        for param in parameters:
            paths = generate_graph(all_packets, filename_prefix="network_stats", parameter_name=param)
            print(f"Generated {param} graphs:")
            print(f" → HTML: {paths['html']}")
            print(f" → PNG : {paths['png']}")

    except Exception as e:
        print(f"Error generating graphs: {e}")
