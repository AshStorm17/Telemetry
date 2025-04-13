from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_socketio import SocketIO
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user,
)
import logging
import os

# Import our modules
from config import Config
from models import db
from models.device import Device
from models.metric import Metric, MetricHistory
from utils.telemetry import TelemetryCollector

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize telemetry collector
telemetry_collector = TelemetryCollector(app)
telemetry_collector.init_app(app, socketio)

#########################
# Routes
#########################

@app.route("/")
def index():
    """Render the main dashboard page"""
    return render_template("dashboard.html")


@app.route("/devices")
def devices():
    """Render the device management page"""
    device_list = Device.query.all()
    return render_template("devices.html", devices=device_list)


@app.route("/devices/add", methods=["POST"])
def add_device():
    """Add a new network device"""
    try:
        device = Device(
            name=request.form.get("name"),
            ip_address=request.form.get("ip_address"),
            device_type=request.form.get("device_type"),
            location=request.form.get("location"),
            snmp_community=request.form.get("snmp_community", "public"),
            snmp_port=int(request.form.get("snmp_port", 161)),
        )
        db.session.add(device)
        db.session.commit()
        flash("Device added successfully", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error adding device: {str(e)}", "danger")

    return redirect(url_for("devices"))


@app.route("/devices/<int:device_id>/delete", methods=["POST"])
def delete_device(device_id):
    """Delete a network device"""
    try:
        device = Device.query.get_or_404(device_id)
        db.session.delete(device)
        db.session.commit()
        flash("Device deleted successfully", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting device: {str(e)}", "danger")

    return redirect(url_for("devices"))


@app.route("/devices/<int:device_id>/toggle", methods=["POST"])
def toggle_device(device_id):
    """Toggle the active status of a device"""
    try:
        device = Device.query.get_or_404(device_id)
        device.is_active = not device.is_active
        db.session.commit()
        status = "activated" if device.is_active else "deactivated"
        flash(f"Device {status} successfully", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error toggling device status: {str(e)}", "danger")

    return redirect(url_for("devices"))


#########################
# API Routes
#########################

@app.route("/api/devices")
def api_devices():
    """API endpoint to get all devices"""
    devices = Device.query.all()
    return jsonify([device.to_dict() for device in devices])


@app.route("/api/devices/<int:device_id>")
def api_device(device_id):
    """API endpoint to get a specific device"""
    device = Device.query.get_or_404(device_id)
    return jsonify(device.to_dict())


@app.route("/api/metrics/<int:device_id>")
def api_metrics(device_id):
    """API endpoint to get metrics for a specific device"""
    metric_type = request.args.get("type")
    limit = request.args.get("limit", type=int)

    metrics = telemetry_collector.get_device_metrics(device_id, metric_type, limit)
    return jsonify(metrics)


@app.route("/api/latest-metrics")
def api_latest_metrics():
    """API endpoint to get the latest metrics for all devices"""
    latest_metrics = MetricHistory.get_all_latest_metrics()
    return jsonify(latest_metrics)


#########################
# SocketIO Events
#########################

@socketio.on("connect")
def handle_connect():
    """Handle client connection"""
    logger.info("Client connected")


@socketio.on("disconnect")
def handle_disconnect():
    """Handle client disconnection"""
    logger.info("Client disconnected")


@socketio.on("request_update")
def handle_update_request(data):
    """Handle request for immediate telemetry update"""
    latest_metrics = MetricHistory.get_all_latest_metrics()
    socketio.emit("telemetry_update", latest_metrics, room=request.sid)


__all__ = ["app", "socketio", "telemetry_collector"]
