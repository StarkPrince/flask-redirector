import os
from dotenv import load_dotenv
from app import app, db, User

def setup_database():
    """Initialize the database and create admin user."""
    with app.app_context():
        # Create all tables
        db.create_all()
        print("Database initialized successfully!")

        # Create admin user if it doesn't exist
        admin_username = os.getenv('ADMIN_USERNAME')
        admin_password = os.getenv('ADMIN_PASSWORD')

        if not admin_username or not admin_password:
            print("Error: ADMIN_USERNAME and ADMIN_PASSWORD must be set in .env file")
            return

        existing_user = User.query.filter_by(username=admin_username).first()
        if not existing_user:
            admin_user = User(username=admin_username)
            admin_user.set_password(admin_password)
            db.session.add(admin_user)
            db.session.commit()
            print(f"Admin user '{admin_username}' created successfully!")
        else:
            print(f"Admin user '{admin_username}' already exists!")

if __name__ == '__main__':
    load_dotenv()
    setup_database() 