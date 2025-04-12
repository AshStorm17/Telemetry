import plotly.graph_objects as go
import os

def generate_graph(data, filename):
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        y=data['Total Packets'], 
        x=data['Latest Timestamp'], 
        mode='lines+markers',
        name='Total Packets'
    ))

    output_path = os.path.join('static', 'graphs', f"{filename}.html")
    fig.write_html(output_path, auto_open=False)
    return f"/static/graphs/{filename}.html"
