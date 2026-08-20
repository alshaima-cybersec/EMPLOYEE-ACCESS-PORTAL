"""
models.py -- Secure Portal

Implements the mitigated data layer:
  - Passwords stored as salted Werkzeug hashes (never in plaintext/reversible form)
  - Lockout tracking (failed_attempts / locked_until) enforced in app.py
  - AuditLog table populated for every security-relevant event
"""
from datetime import datetime, timedelta

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 10


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)

    # SECURE: salted hash via Werkzeug (pbkdf2:sha256 by default).
    password_hash = db.Column(db.String(255), nullable=False)

    role = db.Column(db.String(20), nullable=False, default="employee")  # 'employee' | 'admin'
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    failed_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # ------------------------------------------------------------------
    # Password handling
    # ------------------------------------------------------------------
    def set_password(self, raw_password: str) -> None:
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password: str) -> bool:
        return check_password_hash(self.password_hash, raw_password)

    # ------------------------------------------------------------------
    # Lockout handling
    # ------------------------------------------------------------------
    def is_locked(self) -> bool:
        return bool(self.locked_until and self.locked_until > datetime.utcnow())

    def register_failed_attempt(self) -> None:
        self.failed_attempts = (self.failed_attempts or 0) + 1
        if self.failed_attempts >= MAX_FAILED_ATTEMPTS:
            self.locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)

    def register_successful_login(self) -> None:
        self.failed_attempts = 0
        self.locked_until = None

    def unlock(self) -> None:
        self.failed_attempts = 0
        self.locked_until = None

    def is_admin(self) -> bool:
        return self.role == "admin"


class AuditLog(db.Model):
    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    username = db.Column(db.String(120), nullable=True)
    event_type = db.Column(db.String(50), nullable=False)
    result = db.Column(db.String(20), nullable=False)  # 'success' | 'failure'
    ip_address = db.Column(db.String(45), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


def log_event(db_session, event_type: str, result: str, username: str = None,
              user_id: int = None, ip_address: str = None) -> None:
    """Central helper used by app.py to write every audit event consistently."""
    entry = AuditLog(
        user_id=user_id,
        username=username,
        event_type=event_type,
        result=result,
        ip_address=ip_address,
    )
    db_session.add(entry)
    db_session.commit()
