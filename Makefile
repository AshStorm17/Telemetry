# Makefile for Flask application database management

DB_PATH=app.db
FLASK_APP=app.py

.PHONY: create-db drop-db add-devices init-db clean

create-db:
	@echo "Creating database..."
	python scripts/create_db.py
	@echo "Database created successfully."

add-devices:
	@echo "Adding sample devices..."
	python scripts/add_devices.py
	@echo "Sample devices added successfully."

drop-db:
	@echo "Dropping database..."
	python scripts/drop_db.py
	@echo "Database dropped successfully."

init-db: create-db add-devices
	@echo "Database initialized with sample data."

clean: drop-db
	@if [ -f "$(DB_PATH)" ]; then \
		echo "Deleting the database file..."; \
		rm "$(DB_PATH)"; \
		echo "Database file deleted successfully."; \
	else \
		echo "Database file does not exist."; \
	fi
	@echo "Database completely cleaned up."