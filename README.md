# 📡 Telemetry – Intelligent Health Monitoring via Network Traffic

A Flask-based visualization and inference platform for monitoring network health and performance using data collected from software-defined network (SDN) switches.

---
## 🧠 Project Workflow
1. **Switches** generate telemetry data and send it to **cluster nodes**.
2. **Cluster nodes** forward this to a centralized **cluster center**.
3. The **cluster center** parses the packets and forwards only the essential packet info to the **data center**.
4. The **data center** uses trained ML models to infer health metrics like congestion, anomalies, or QoS degradation.
5. Results are visualized on the **Flask web app** in real time.
---

## 🔧 Project Structure
```
Telemetry/
├── [app.py]               # Main Flask application entry point
├── static/                # Static files (CSS, JavaScript, images)
│   ├── css/
│   ├── js/
│   └── images/
├── templates/             # HTML templates for the Flask app
│   └── dashboard.html     # Main dashboard template
├── models/                # Machine learning models and scripts
│   └── model.pkl          # Pre-trained ML model
├── data/                  # Telemetry data and logs
│   ├── raw/               # Raw telemetry data
│   └── processed/         # Processed data for visualization
├── tests/                 # Unit and integration tests
│   └── test_app.py        # Tests for the Flask app
├── [requirements.txt](http://_vscodecontentref_/2)       # Python dependencies
├── [README.md](http://_vscodecontentref_/3)              # Project documentation
└── LICENSE                # License file
```
