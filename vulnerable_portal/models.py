"""
models.py -- Vulnerable Portal

EDUCATIONAL WARNING:
This module intentionally demonstrates INSECURE password storage
(unsalted MD5) for comparison against the secure_portal implementation,
which uses Werkzeug's salted password hashing. Never use this pattern
in a real application.
"""
import hashlib
from datetime import datetime

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def weak_hash(password: str) -> str:
    """
    INSECURE: unsalted MD5. Fast to brute force, no per-user salt,
    identical passwords produce identical hashes (rainbow-table friendly).
    Included ONLY to give students something concrete to compare against
    the secure version's Werkzeug-based hashing.
    """
    return hashlib.md5(password.encode("utf-8")).hexdigest()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

    # VULNERABLE: weak, unsalted hash stored directly.
    password = db.Column(db.String(255), nullable=False)

    role = db.Column(db.String(20), nullable=False, default="employee")  # 'employee' | 'admin'
    is_active = db.Column(db.Boolean, default=True)

    # No lockout tracking in the vulnerable version by design.
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, raw_password: str):
        # VULNERABLE: no complexity check, no salt.
        self.password = weak_hash(raw_password)

    def check_password(self, raw_password: str) -> bool:
        return self.password == weak_hash(raw_password)

    def is_admin(self) -> bool:
        return self.role == "admin"


class AuditLog(db.Model):
    """
    Present for schema parity with the secure version, but the vulnerable
    app intentionally does NOT write to this table (missing audit logging
    is one of the demonstrated weaknesses).
    """
    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    username = db.Column(db.String(120), nullable=True)
    event_type = db.Column(db.String(50), nullable=False)
    result = db.Column(db.String(20), nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
