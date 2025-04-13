#!/bin/bash

# Set Flask app entry point
export FLASK_APP=wsgi.py

# Optional: activate virtual environment
# source venv/bin/activate

# Path to the database file (if using SQLite)
DB_PATH="app.db"

create_db() {
    echo "Creating database..."
    flask shell <<EOF
from app import app
from models import db
with app.app_context():
    db.create_all()
EOF
    echo "Database created successfully."
}

add_sample_devices() {
    echo "Adding sample devices..."
    flask shell <<EOF
from app import app
from models import db
from models.device import Device
with app.app_context():
    if Device.query.count() == 0:
        sample_devices = [
            Device(name="Core Router", ip_address="192.168.1.1", device_type="router", location="Data Center"),
            Device(name="Edge Switch 1", ip_address="192.168.1.2", device_type="switch", location="Main Office"),
            Device(name="Firewall", ip_address="192.168.1.3", device_type="firewall", location="Data Center"),
            Device(name="Distribution Switch", ip_address="192.168.1.4", device_type="switch", location="Branch Office"),
            Device(name="Access Point", ip_address="192.168.1.5", device_type="access_point", location="Conference Room"),
        ]
        for device in sample_devices:
            db.session.add(device)
        db.session.commit()
        print("Sample devices added.")
    else:
        print("Devices already exist.")
EOF
}

drop_db() {
    echo "Dropping all tables from the database..."
    flask shell <<EOF
from app import app
from models import db
with app.app_context():
    db.drop_all()
EOF
    echo "All tables dropped successfully."
}

delete_db_file() {
    if [ -f "$DB_PATH" ]; then
        echo "Deleting the database file..."
        rm "$DB_PATH"
        echo "Database file deleted successfully."
    else
        echo "Database file does not exist."
    fi
}

show_menu() {
    echo ""
    echo "===== Database Management Menu ====="
    echo "1) Create database tables"
    echo "2) Add sample devices"
    echo "3) Drop all tables"
    echo "4) Delete database file"
    echo "5) Exit"
    read -p "Select an option [1-5]: " option
    case $option in
        1) create_db ;;
        2) add_sample_devices ;;
        3) drop_db ;;
        4) delete_db_file ;;
        5) echo "Goodbye!"; exit ;;
        *) echo "Invalid option." ;;
    esac
}

# Loop menu
while true; do
    show_menu
done
