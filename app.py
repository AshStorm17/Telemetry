from flask import Flask, render_template
import os
from utils.parse_pcap import parse_pcap_file
from utils.model_inference import infer_health_metrics

app = Flask(__name__)
PCAP_DIR = 'Network'

@app.route('/')
def dashboard():
    pcap_files = [f for f in os.listdir(PCAP_DIR) if f.endswith('.pcap')]
    graphs = []

    for file in pcap_files:
        path = os.path.join(PCAP_DIR, file)
        raw_data = parse_pcap_file(path)
        inferred_metrics = infer_health_metrics(raw_data)  # from ML model
        graphs.append({
            "filename": file,
            "data": inferred_metrics
        })

    return render_template('dashboard.html', graphs=graphs)

if __name__ == '__main__':
    app.run(debug=True)
