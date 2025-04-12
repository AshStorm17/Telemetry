import os
from datetime import timedelta

# Base directory of the application
BASE_DIR = os.path.abspath(os.path.dirname(__file__))


# Flask configuration
class Config:
    # Security
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-key-change-in-production")

    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f'sqlite:///{os.path.join(BASE_DIR, "app.db")}'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)

    # SocketIO
    SOCKETIO_PING_TIMEOUT = 10
    SOCKETIO_PING_INTERVAL = 25

    # Telemetry settings
    TELEMETRY_UPDATE_INTERVAL = 5  # seconds
    TELEMETRY_HISTORY_LIMIT = 100  # data points to keep per metric

    # Network parameters to collect
    NETWORK_PARAMETERS = [
        "bandwidth_usage",  # in Mbps
        "packet_loss",  # in percentage
        "latency",  # in ms
        "cpu_usage",  # in percentage
        "memory_usage",  # in percentage
        "error_rate",  # errors per second
    ]
