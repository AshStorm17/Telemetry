from datetime import datetime
import json
from . import db


class Metric(db.Model):
    """
    Model representing telemetry metrics from network devices
    """

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey("device.id"), nullable=False)
    metric_type = db.Column(
        db.String(50), nullable=False
    )  # bandwidth_usage, packet_loss, latency, etc.
    value = db.Column(db.Float, nullable=False)
    unit = db.Column(db.String(20), nullable=False)  # Mbps, %, ms, etc.
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Metric {self.metric_type} for device {self.device_id}: {self.value} {self.unit}>"

    def to_dict(self):
        """Convert metric to dictionary for API responses"""
        return {
            "id": self.id,
            "device_id": self.device_id,
            "metric_type": self.metric_type,
            "value": self.value,
            "unit": self.unit,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }


class MetricHistory:
    """
    Class for managing metric history in memory (for quick access to recent data)
    """

    _history = {}  # device_id -> metric_type -> [list of (timestamp, value) tuples]

    @classmethod
    def add_metric(cls, device_id, metric_type, value, timestamp, max_history=100):
        """Add a metric to the history"""
        if device_id not in cls._history:
            cls._history[device_id] = {}

        if metric_type not in cls._history[device_id]:
            cls._history[device_id][metric_type] = []

        # Add the new data point
        cls._history[device_id][metric_type].append((timestamp, value))

        # Trim the history if it's too long
        if len(cls._history[device_id][metric_type]) > max_history:
            cls._history[device_id][metric_type] = cls._history[device_id][metric_type][
                -max_history:
            ]

    @classmethod
    def get_device_metrics(cls, device_id, metric_type=None):
        """Get metrics for a device, optionally filtered by metric type"""
        if device_id not in cls._history:
            return {}

        if metric_type:
            if metric_type in cls._history[device_id]:
                return {metric_type: cls._history[device_id][metric_type]}
            return {}

        return cls._history[device_id]

    @classmethod
    def get_all_latest_metrics(cls):
        """Get the latest value of each metric for all devices"""
        result = {}
        for device_id, metrics in cls._history.items():
            result[device_id] = {}
            for metric_type, values in metrics.items():
                if values:  # If there's at least one value
                    result[device_id][metric_type] = values[-1]  # Get the latest
        return result

    @classmethod
    def clear_history(cls):
        """Clear all history data"""
        cls._history = {}
