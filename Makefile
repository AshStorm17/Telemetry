# Makefile for Flask application database management

DB_PATH=Telemetry/app.db
FLASK_APP=app.py

.PHONY: create-db drop-db delete-db add-devices

create-db:
	@echo "Creating database..."
	flask shell -c "from app import db; db.create_all()"
	@echo "Database created successfully."

add-devices:
	@echo "Adding sample devices..."
	flask shell -c "\
	from app import db; \
	from models.device import Device; \
	devices = [ \
		Device(name='Core Router', ip_address='192.168.1.1', device_type='router', location='Data Center'), \
		Device(name='Edge Switch 1', ip_address='192.168.1.2', device_type='switch', location='Main Office'), \
		Device(name='Firewall', ip_address='192.168.1.3', device_type='firewall', location='Data Center'), \
		Device(name='Distribution Switch', ip_address='192.168.1.4', device_type='switch', location='Branch Office'), \
		Device(name='Access Point', ip_address='192.168.1.5', device_type='access_point', location='Conference Room') \
	]; \
	for device in devices: \
		db.session.add(device); \
	db.session.commit()"
	@echo "Sample devices added successfully."

drop-db:
	@echo "Dropping database..."
	flask shell -c "from app import db; db.drop_all()"
	@echo "Database dropped successfully."

delete-db:
	@if [ -f "$(DB_PATH)" ]; then \
		echo "Deleting the database file..."; \
		rm "$(DB_PATH)"; \
		echo "Database file deleted successfully."; \
	else \
		echo "Database file does not exist."; \
	fi

init-db: create-db add-devices
	@echo "Database initialized with sample data."

clean: drop-db delete-db
	@echo "Database completely cleaned up."