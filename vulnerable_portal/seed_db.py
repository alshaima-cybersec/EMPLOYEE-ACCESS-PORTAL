"""
seed_db.py -- Vulnerable Portal

Creates the SQLite database and inserts two demonstration accounts.
Run this once before starting app.py:

    python seed_db.py
"""
import os
from app import app
from models import db, User

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")


def seed():
    os.makedirs(INSTANCE_DIR, exist_ok=True)

    with app.app_context():
        db.create_all()

        if User.query.filter_by(email="admin@example.com").first() is None:
            admin = User(
                full_name="Alice Administrator",
                email="admin@example.com",
                role="admin",
                is_active=True,
            )
            # VULNERABLE: weak demo password accepted with no complexity check.
            admin.set_password("admin123")
            db.session.add(admin)

        if User.query.filter_by(email="employee@example.com").first() is None:
            employee = User(
                full_name="Evan Employee",
                email="employee@example.com",
                role="employee",
                is_active=True,
            )
            employee.set_password("password")
            db.session.add(employee)

        db.session.commit()
        print("Vulnerable portal database seeded.")
        print("  admin@example.com     / admin123")
        print("  employee@example.com  / password")


if __name__ == "__main__":
    seed()
