import random
import time
from datetime import datetime
import threading
import logging
from models.metric import Metric, MetricHistory
from models import db

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TelemetryCollector:
    """
    Class for collecting telemetry data from network devices

    In a real-world scenario, this would use SNMP, sFlow, NetFlow, gRPC, or other
    protocols to collect data from actual devices. For this example, we generate
    simulated data.
    """

    def __init__(self, app=None):
        self.app = app
        self.running = False
        self.collection_thread = None
        self.socketio = None

        # If app is provided, initialize with the app
        if app is not None:
            self.init_app(app)

    def init_app(self, app, socketio=None):
        """Initialize with Flask app and optional SocketIO instance"""
        self.app = app
        self.socketio = socketio

        # Get configuration values
        self.update_interval = app.config.get("TELEMETRY_UPDATE_INTERVAL", 5)
        self.history_limit = app.config.get("TELEMETRY_HISTORY_LIMIT", 100)
        self.parameters = app.config.get(
            "NETWORK_PARAMETERS",
            [
                "bandwidth_usage",
                "packet_loss",
                "latency",
                "cpu_usage",
                "memory_usage",
                "error_rate",
            ],
        )

    def start_collection(self):
        """Start the telemetry collection thread"""
        if self.running:
            logger.warning("Telemetry collection already running")
            return

        self.running = True
        self.collection_thread = threading.Thread(target=self._collection_loop)
        self.collection_thread.daemon = True
        self.collection_thread.start()
        logger.info("Telemetry collection started")

    def stop_collection(self):
        """Stop the telemetry collection thread"""
        self.running = False
        if self.collection_thread:
            self.collection_thread.join(timeout=5)
        logger.info("Telemetry collection stopped")

    def _collection_loop(self):
        """Main collection loop that runs in a separate thread"""
        while self.running:
            try:
                with self.app.app_context():
                    # Get all active devices from the database
                    from models.device import Device

                    devices = Device.query.filter_by(is_active=True).all()

                    for device in devices:
                        # In a real application, this is where you would query the device
                        # using SNMP, API calls, etc.
                        self._collect_device_metrics(device)

                    # Commit any database changes
                    db.session.commit()

                    # Emit updated data via SocketIO if available
                    if self.socketio:
                        latest_metrics = MetricHistory.get_all_latest_metrics()
                        self.socketio.emit("telemetry_update", latest_metrics)

            except Exception as e:
                logger.error(f"Error in telemetry collection: {e}")

            # Sleep until next collection interval
            time.sleep(self.update_interval)

    def _collect_device_metrics(self, device):
        """Collect metrics for a specific device"""
        # In this example, we generate simulated data
        # In a real application, this would query the device via SNMP, API, etc.
        timestamp = datetime.utcnow()

        # Generate metrics based on the configured parameters
        for param in self.parameters:
            value = self._simulate_metric_value(param, device)
            unit = self._get_unit_for_metric(param)

            # Create a new metric record
            metric = Metric(
                device_id=device.id,
                metric_type=param,
                value=value,
                unit=unit,
                timestamp=timestamp,
            )

            # Add to database
            db.session.add(metric)

            # Add to in-memory history for quick access
            MetricHistory.add_metric(
                device_id=device.id,
                metric_type=param,
                value=value,
                timestamp=timestamp,
                max_history=self.history_limit,
            )

    def _simulate_metric_value(self, metric_type, device):
        """
        Generate simulated metric values

        In a real application, this would be replaced with actual data collection
        from network devices using protocols like SNMP.
        """
        # Base values and variations for different metric types
        base_values = {
            "bandwidth_usage": 500,  # Base around 500 Mbps
            "packet_loss": 0.5,  # Base around 0.5%
            "latency": 15,  # Base around 15 ms
            "cpu_usage": 30,  # Base around 30%
            "memory_usage": 45,  # Base around 45%
            "error_rate": 2,  # Base around 2 errors/sec
        }

        variations = {
            "bandwidth_usage": 100,  # +/- 100 Mbps
            "packet_loss": 0.3,  # +/- 0.3%
            "latency": 5,  # +/- 5 ms
            "cpu_usage": 10,  # +/- 10%
            "memory_usage": 15,  # +/- 15%
            "error_rate": 1,  # +/- 1 error/sec
        }

        # Get base value and variation
        base = base_values.get(metric_type, 50)
        variation = variations.get(metric_type, 10)

        # Generate a random value within the range
        value = base + (random.random() * 2 - 1) * variation

        # Ensure values are within reasonable bounds
        if metric_type in ["packet_loss", "cpu_usage", "memory_usage"]:
            value = max(0, min(100, value))  # 0-100% range
        elif metric_type == "error_rate":
            value = max(0, value)  # Can't have negative errors
        elif metric_type == "bandwidth_usage":
            value = max(0, value)  # Can't have negative bandwidth

        return round(value, 2)

    def _get_unit_for_metric(self, metric_type):
        """Get the appropriate unit for a metric type"""
        units = {
            "bandwidth_usage": "Mbps",
            "packet_loss": "%",
            "latency": "ms",
            "cpu_usage": "%",
            "memory_usage": "%",
            "error_rate": "errors/sec",
        }
        return units.get(metric_type, "")

    def get_device_metrics(self, device_id, metric_type=None, limit=None):
        """
        Get metrics for a specific device

        Args:
            device_id: ID of the device
            metric_type: Optional type of metric to filter by
            limit: Maximum number of records to return

        Returns:
            Dictionary of metrics data
        """
        # First try to get from in-memory history
        metrics = MetricHistory.get_device_metrics(device_id, metric_type)

        # If not in memory or we need more historical data, query the database
        if not metrics or (limit and limit > self.history_limit):
            with self.app.app_context():
                query = Metric.query.filter_by(device_id=device_id)

                if metric_type:
                    query = query.filter_by(metric_type=metric_type)

                if limit:
                    query = query.order_by(Metric.timestamp.desc()).limit(limit)
                else:
                    query = query.order_by(Metric.timestamp.desc())

                db_metrics = query.all()

                # Convert to same format as in-memory data
                result = {}
                for metric in db_metrics:
                    if metric.metric_type not in result:
                        result[metric.metric_type] = []

                    result[metric.metric_type].append((metric.timestamp, metric.value))

                # Sort by timestamp (oldest first)
                for metric_type in result:
                    result[metric_type].sort(key=lambda x: x[0])

                return result

        return metrics
