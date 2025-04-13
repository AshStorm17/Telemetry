from flask import Flask, render_template
import threading, time, os
from utils.packet_parser import parse_custom_csv
from utils.plot_graphs import generate_graph

app = Flask(__name__)
CSV_DIR = 'network/MERGER'
graph_metadata = []

def live_updater():
    while True:
        csv_files = [f for f in os.listdir(CSV_DIR) if f.endswith('.csv')]
        graph_metadata.clear()

        for file in csv_files:
            path = os.path.join(CSV_DIR, file)
            data = parse_custom_csv(path)
            graph_url = generate_graph(data, filename=file.replace('.csv', ''))
            graph_metadata.append({
                "filename": file,
                "graph_url": graph_url
            })

        time.sleep(5)  # Check every 5 seconds

@app.route('/')
def dashboard():
    return render_template("dashboard.html", graphs=graph_metadata)

if __name__ == '__main__':
    thread = threading.Thread(target=live_updater, daemon=True)
    thread.start()
    app.run(debug=True)
