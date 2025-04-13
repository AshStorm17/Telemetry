import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from models import db
from app import app  # Import the existing app object

def drop_database():
    db.drop_all()

if __name__ == '__main__':
    with app.app_context():  # Use the app's application context
        drop_database()