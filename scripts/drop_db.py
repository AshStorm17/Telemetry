from ..models import db

def drop_database():
    db.drop_all()

if __name__ == '__main__':
    drop_database()