from ..models import db

def create_database():
    db.create_all()

if __name__ == '__main__':
    create_database()