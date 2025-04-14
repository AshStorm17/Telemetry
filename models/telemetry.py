from datetime import datetime
from . import db


class TelemetryData(db.Model):
    """
    Model representing telemetry data for a network device.
    """

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    mac = db.Column(db.String(50), nullable=False)
    parameter_name = db.Column(db.String(100), nullable=False)
    value = db.Column(db.Float, nullable=False)

    # Foreign key to associate telemetry data with a device
    device_id = db.Column(db.Integer, db.ForeignKey("device.id"), nullable=False)

    def __repr__(self):
        return f"<TelemetryData {self.parameter_name} for MAC {self.mac} at {self.timestamp}>"

    def to_dict(self):
        """Convert telemetry data to dictionary for API responses"""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "mac": self.mac,
            "parameter_name": self.parameter_name,
            "value": self.value,
            "device_id": self.device_id,
        }