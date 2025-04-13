#!/bin/bash

# This script manages the database tasks for the Flask application.

# Set the location of the app.db file
DB_PATH="Telemetry/app.db"

# Create the database (This will create the tables)
create_db() {
    echo "Creating database..."
    flask shell <<EOF
from app import db
db.create_all()
EOF
    echo "Database created successfully."
}

# Add sample devices (if the database is empty)
add_sample_devices() {
    echo "Adding sample devices..."
    flask shell <<EOF
from app import db
from models.device import Device

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
EOF
    echo "Sample devices added successfully."
}

# Drop the database (Use with caution)
drop_db() {
    echo "Dropping database..."
    flask shell <<EOF
from app import db
db.drop_all()
EOF
    echo "Database dropped successfully."
}

# Delete the database file (Use with caution)
delete_db_file() {
    if [ -f "$DB_PATH" ]; then
        echo "Deleting the database file..."
        rm "$DB_PATH"
        echo "Database file deleted successfully."
    else
        echo "Database file does not exist."
    fi
}

# Show menu for options
show_menu() {
    echo "Database Management Options:"
    echo "1) Create database"
    echo "2) Add sample devices"
    echo "3) Drop database"
    echo "4) Delete database file"
    echo "5) Exit"
    read -p "Select an option: " option
    case $option in
        1) create_db ;;
        2) add_sample_devices ;;
        3) drop_db ;;
        4) delete_db_file ;;
        5) exit ;;
        *) echo "Invalid option" ;;
    esac
}

# Show menu loop
while true; do
    show_menu
done
