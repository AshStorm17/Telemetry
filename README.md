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
├── app.py               # Main Flask application entry point
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
├── requirements.txt     # Python dependencies
├── README.md           # Project documentation
└── LICENSE                # License file
```


# Network Telemetry Dashboard

A real-time monitoring solution for network devices that visualizes critical health parameters including bandwidth usage, packet loss, latency, CPU and memory utilization, and error rates.

<!-- ![Dashboard Preview](docs/dashboard_preview.png) -->

## 🌟 Features

- **Real-time Monitoring**: Live updates of network metrics using WebSockets
- **Interactive Visualization**: Responsive charts with customizable time ranges
- **Device Management**: Add, remove, and configure network devices through a user-friendly interface
- **Scalable Architecture**: Designed to handle multiple devices with minimal overhead
- **Lightweight Implementation**: Uses Flask for both backend and frontend components

## 📋 Requirements

- Python 3.8+
- pip package manager
- Virtual environment (also provided: 'venv') (recommended)

## 🚀 Installation

1. **Clone the repository**

```bash
git clone https://github.com/AshStorm17/Telemetry/tree/main/web%20portal/network_telemetry_dashboard
cd network-telemetry-dashboard
```

2. **Create and activate a virtual environment**

```bash
# Create virtual environment
python -m venv venv

# Activate on Windows
venv\Scripts\activate

# Activate on macOS/Linux
source venv/bin/activate
```

3. **Install dependencies**

```bash
pip install -r requirements.txt
```

4. **Run the application**

```bash
python app.py
```

> **Note for macOS users**: If you encounter a port conflict with AirPlay on port 5000, either disable AirPlay Receiver in System Settings or modify the port in `app.py` to use port 5001.

5. **Access the dashboard**

Open your browser and navigate to:
```
http://localhost:5000
```
(or http://localhost:5001 if you are using MacOS)

## 🔧 Configuration

The application can be configured by editing the `config.py` file:

- `TELEMETRY_UPDATE_INTERVAL`: Time between telemetry updates (seconds)
- `TELEMETRY_HISTORY_LIMIT`: Number of data points to keep per metric
- `NETWORK_PARAMETERS`: The network metrics to collect and display

## 🏗️ Project Structure

```
network_telemetry_dashboard/
├── app.py               # Main Flask application
├── config.py            # Configuration settings
├── requirements.txt     # Dependencies
├── static/              # Static files
│   ├── css/
│   │   └── style.css    # Custom styles
│   └── js/
│       ├── dashboard.js # Dashboard functionality
│       └── charts.js    # Chart configurations
├── templates/           # HTML templates
│   ├── base.html        # Base template
│   ├── dashboard.html   # Main dashboard
│   └── devices.html     # Device management
├── models/              # Data models
│   ├── __init__.py
│   ├── device.py        # Network device model
│   └── metric.py        # Telemetry metrics model
└── utils/               # Utility functions
    ├── __init__.py
    └── telemetry.py     # Telemetry data collector
```

## 💻 Technologies Used

- **Backend**: Flask, Flask-SocketIO, SQLAlchemy
- **Frontend**: HTML5, CSS3, JavaScript, Bootstrap 5
- **Data Visualization**: Chart.js
- **Real-time Communication**: Socket.IO
- **Database**: SQLite (default), extensible to other databases

## 🔍 Customizing for Real Network Devices

The current implementation uses simulated data, as of now but will surely be updated with the real data soon. To add/collect specific metrics from network devices:

1. Modify the `TelemetryCollector` class in `utils/telemetry.py` to connect to your devices using SNMP, API calls, or other protocols.
2. Adjust the parameters in `config.py` to match your specific monitoring needs.
3. Update the device model if you need to store additional device-specific information.

Example SNMP integration (requires additional setup):

```python
from pysnmp.hlapi import *

def get_device_bandwidth(device):
    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(SnmpEngine(),
               CommunityData(device.snmp_community),
               UdpTransportTarget((device.ip_address, device.snmp_port)),
               ContextData(),
               ObjectType(ObjectIdentity('IF-MIB', 'ifInOctets', 1)),
               ObjectType(ObjectIdentity('IF-MIB', 'ifOutOctets', 1)))
    )
    
    # Process the results
    if errorIndication:
        print(f"Error: {errorIndication}")
        return 0
    else:
        # Calculate bandwidth from octet values
        # ...
        return bandwidth_value
```

## 📊 Available Metrics

The dashboard currently supports these metrics:

- **Bandwidth Usage**: Network throughput in Mbps
- **Packet Loss**: Percentage of dropped packets
- **Latency**: Network delay in milliseconds
- **CPU Usage**: Device processor utilization percentage
- **Memory Usage**: Device memory utilization percentage
- **Error Rate**: Network errors per second

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👥 Contributors

- Jaidev Sanjay Khalane
- Vannsh Jani
- John Debbarma
- Mrigankashekhar Shandilya
- Kristopher Paul
- Aashmun Gupta

## 📞 Support

For questions or support, please open an issue on the GitHub repository or contact the team members listed above.
