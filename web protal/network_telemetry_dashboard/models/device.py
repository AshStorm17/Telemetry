from datetime import datetime
from . import db


class Device(db.Model):
    """
    Model representing a network device (router, switch, etc.)
    """

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(50), unique=True, nullable=False)
    device_type = db.Column(
        db.String(50), nullable=False
    )  # router, switch, firewall, etc.
    location = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    is_active = db.Column(db.Boolean, default=True)

    # SNMP community string (in production, use more secure methods)
    snmp_community = db.Column(db.String(50), default="public")
    snmp_port = db.Column(db.Integer, default=161)

    # Relationships
    metrics = db.relationship(
        "Metric", backref="device", lazy=True, cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<Device {self.name} ({self.ip_address})>"

    def to_dict(self):
        """Convert device to dictionary for API responses"""
        return {
            "id": self.id,
            "name": self.name,
            "ip_address": self.ip_address,
            "device_type": self.device_type,
            "location": self.location,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
