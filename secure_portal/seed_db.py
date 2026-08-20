"""
seed_db.py -- Secure Portal

Creates the SQLite database and inserts two demonstration accounts with
strong demo passwords (see README.md). Run this once before starting app.py:

    python seed_db.py
"""
import os
from app import app
from models import db, User

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")

# These meet the app's own complexity policy (12+ chars, upper/lower/number/special).
# They are DEMO credentials only -- the README instructs users to change them
# immediately via the Change Password page before any real use.
DEMO_ADMIN_PASSWORD = "AdminPass!2026"
DEMO_EMPLOYEE_PASSWORD = "EmployeePass!2026"


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
            admin.set_password(DEMO_ADMIN_PASSWORD)
            db.session.add(admin)

        if User.query.filter_by(email="employee@example.com").first() is None:
            employee = User(
                full_name="Evan Employee",
                email="employee@example.com",
                role="employee",
                is_active=True,
            )
            employee.set_password(DEMO_EMPLOYEE_PASSWORD)
            db.session.add(employee)

        db.session.commit()
        print("Secure portal database seeded.")
        print(f"  admin@example.com     / {DEMO_ADMIN_PASSWORD}")
        print(f"  employee@example.com  / {DEMO_EMPLOYEE_PASSWORD}")
        print("  Change these demo passwords before any real use.")


if __name__ == "__main__":
    seed()
