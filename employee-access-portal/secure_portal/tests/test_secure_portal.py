"""
tests/test_secure_portal.py

Covers the required test cases:
  1. Correct employee login
  2. Incorrect password
  3. Lockout after five failures
  4. Weak password rejected
  5. Strong password accepted
  6. Employee blocked from admin route
  7. Administrator allowed into admin route
  8. Disabled account blocked
  9. Session timeout
  10. Audit log created
  11. Password stored as a hash (never plaintext)
  12. Logout invalidates the session

Run with:  pytest -v   (from inside secure_portal/, with the venv active)
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app as flask_app  # noqa: E402
from models import db, User, AuditLog  # noqa: E402

ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD = "AdminPass!2026"
EMPLOYEE_EMAIL = "employee@example.com"
EMPLOYEE_PASSWORD = "EmployeePass!2026"


_TEST_DB_FD, _TEST_DB_PATH = tempfile.mkstemp()
flask_app.config.update(
    TESTING=True,
    SQLALCHEMY_DATABASE_URI=f"sqlite:///{_TEST_DB_PATH}",
    WTF_CSRF_ENABLED=False,  # simplifies posting forms directly in tests
)


@pytest.fixture()
def app():
    # Reset schema for every test rather than swapping the DB URI, since
    # Flask-SQLAlchemy caches the engine on the app the first time it's used.
    with flask_app.app_context():
        db.drop_all()
        db.create_all()

        admin = User(full_name="Alice Administrator", email=ADMIN_EMAIL,
                     role="admin", is_active=True)
        admin.set_password(ADMIN_PASSWORD)
        db.session.add(admin)

        employee = User(full_name="Evan Employee", email=EMPLOYEE_EMAIL,
                         role="employee", is_active=True)
        employee.set_password(EMPLOYEE_PASSWORD)
        db.session.add(employee)

        db.session.commit()

    yield flask_app

    with flask_app.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def login(client, email, password):
    return client.post("/login", data={"email": email, "password": password},
                        follow_redirects=True)


# ---------------------------------------------------------------------------
# 1. Correct employee login
# ---------------------------------------------------------------------------
def test_correct_employee_login(client):
    resp = login(client, EMPLOYEE_EMAIL, EMPLOYEE_PASSWORD)
    assert resp.status_code == 200
    assert b"Employee Dashboard" in resp.data


# ---------------------------------------------------------------------------
# 2. Incorrect password
# ---------------------------------------------------------------------------
def test_incorrect_password(client):
    resp = login(client, EMPLOYEE_EMAIL, "totally-wrong-password")
    assert resp.status_code == 200
    assert b"Invalid email or password" in resp.data
    # Should NOT be on the dashboard.
    assert b"Employee Dashboard" not in resp.data


# ---------------------------------------------------------------------------
# 3. Lockout after five failures
# ---------------------------------------------------------------------------
def test_lockout_after_five_failures(app, client):
    for _ in range(5):
        login(client, EMPLOYEE_EMAIL, "wrong-password")

    with app.app_context():
        user = User.query.filter_by(email=EMPLOYEE_EMAIL).first()
        assert user.failed_attempts >= 5
        assert user.is_locked()

    # A 6th attempt, even with the CORRECT password, should be rejected
    # because the account is locked.
    resp = login(client, EMPLOYEE_EMAIL, EMPLOYEE_PASSWORD)
    assert b"temporarily locked" in resp.data
    assert b"Employee Dashboard" not in resp.data


# ---------------------------------------------------------------------------
# 4. Weak password rejected
# ---------------------------------------------------------------------------
def test_weak_password_rejected(client):
    login(client, EMPLOYEE_EMAIL, EMPLOYEE_PASSWORD)
    resp = client.post(
        "/change-password",
        data={
            "current_password": EMPLOYEE_PASSWORD,
            "new_password": "weak",
            "confirm_password": "weak",
        },
        follow_redirects=True,
    )
    assert b"Password must contain" in resp.data


# ---------------------------------------------------------------------------
# 5. Strong password accepted
# ---------------------------------------------------------------------------
def test_strong_password_accepted(app, client):
    login(client, EMPLOYEE_EMAIL, EMPLOYEE_PASSWORD)
    new_password = "BrandNewStrong!Pass9"
    resp = client.post(
        "/change-password",
        data={
            "current_password": EMPLOYEE_PASSWORD,
            "new_password": new_password,
            "confirm_password": new_password,
        },
        follow_redirects=True,
    )
    assert b"Password updated successfully" in resp.data

    with app.app_context():
        user = User.query.filter_by(email=EMPLOYEE_EMAIL).first()
        assert user.check_password(new_password)


# ---------------------------------------------------------------------------
# 6. Employee blocked from admin route
# ---------------------------------------------------------------------------
def test_employee_blocked_from_admin_route(client):
    login(client, EMPLOYEE_EMAIL, EMPLOYEE_PASSWORD)
    resp = client.get("/admin", follow_redirects=True)
    assert b"Access Denied" in resp.data
    assert b"Admin Dashboard" not in resp.data


# ---------------------------------------------------------------------------
# 7. Administrator allowed into admin route
# ---------------------------------------------------------------------------
def test_admin_allowed_into_admin_route(client):
    login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    resp = client.get("/admin", follow_redirects=True)
    assert resp.status_code == 200
    assert b"Admin Dashboard" in resp.data


# ---------------------------------------------------------------------------
# 8. Disabled account blocked
# ---------------------------------------------------------------------------
def test_disabled_account_blocked(app, client):
    with app.app_context():
        user = User.query.filter_by(email=EMPLOYEE_EMAIL).first()
        user.is_active = False
        db.session.commit()

    resp = login(client, EMPLOYEE_EMAIL, EMPLOYEE_PASSWORD)
    assert b"Invalid email or password" in resp.data
    assert b"Employee Dashboard" not in resp.data


# ---------------------------------------------------------------------------
# 9. Session timeout
# ---------------------------------------------------------------------------
def test_session_timeout(client):
    login(client, EMPLOYEE_EMAIL, EMPLOYEE_PASSWORD)

    # Simulate 16 minutes of inactivity by manipulating the session cookie's
    # last_active timestamp directly.
    with client.session_transaction() as sess:
        stale_time = datetime.utcnow() - timedelta(minutes=16)
        sess["last_active"] = stale_time.isoformat()

    resp = client.get("/dashboard", follow_redirects=True)
    assert b"session expired" in resp.data
    assert b"Employee Dashboard" not in resp.data


# ---------------------------------------------------------------------------
# 10. Audit log created
# ---------------------------------------------------------------------------
def test_audit_log_created_on_login(app, client):
    login(client, EMPLOYEE_EMAIL, EMPLOYEE_PASSWORD)

    with app.app_context():
        entries = AuditLog.query.filter_by(event_type="login", result="success").all()
        assert len(entries) == 1
        assert entries[0].username == EMPLOYEE_EMAIL


def test_audit_log_created_on_failed_login(app, client):
    login(client, EMPLOYEE_EMAIL, "wrong-password")

    with app.app_context():
        entries = AuditLog.query.filter_by(event_type="login", result="failure").all()
        assert len(entries) == 1


# ---------------------------------------------------------------------------
# 11. Password stored as a hash (never plaintext)
# ---------------------------------------------------------------------------
def test_password_stored_as_hash(app):
    with app.app_context():
        user = User.query.filter_by(email=EMPLOYEE_EMAIL).first()
        assert user.password_hash != EMPLOYEE_PASSWORD
        assert user.password_hash.startswith(("pbkdf2:", "scrypt:"))


# ---------------------------------------------------------------------------
# 12. Logout invalidates the session
# ---------------------------------------------------------------------------
def test_logout_invalidates_session(client):
    login(client, EMPLOYEE_EMAIL, EMPLOYEE_PASSWORD)
    resp = client.get("/logout", follow_redirects=True)
    assert b"securely logged out" in resp.data

    # Subsequent request to a protected page should redirect to login.
    resp2 = client.get("/dashboard", follow_redirects=True)
    assert b"Sign In" in resp2.data
    assert b"Employee Dashboard" not in resp2.data
