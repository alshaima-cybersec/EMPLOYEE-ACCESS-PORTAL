"""
app.py -- SECURE Employee Access Portal (Educational Demo)

Mitigates every weakness demonstrated in ../vulnerable_portal/app.py:

  1. Weak password storage      -> Werkzeug salted password hashing
  2. Weak password policy       -> 12+ chars, upper/lower/number/special required
  3. Broken access control      -> server-side RBAC decorator on every protected route
  4. Unlimited failed attempts  -> lockout after 5 failures, 10-minute cooldown
  5. Insecure session handling  -> 15-minute idle timeout, HttpOnly/SameSite cookies,
                                    session regenerated on login, cleared on logout
  6. Missing audit logging      -> every security-relevant event is recorded

Run LOCALLY ONLY. Do not deploy this application publicly. It uses fictional
demonstration data and demo credentials that must be changed before any real use.
"""
import os
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for, session, flash, abort
)
from flask_wtf import CSRFProtect
from dotenv import load_dotenv

from models import db, User, AuditLog, log_event
from forms import LoginForm, ChangePasswordForm, RoleChangeForm, EmptyForm

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

app = Flask(__name__)

# SECURE: secret key loaded from environment, never hardcoded/committed.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-fallback-change-me")

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(
    BASE_DIR, "instance", "secure.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# SECURE: session/cookie hardening.
app.config["SESSION_COOKIE_HTTPONLY"] = True          # not accessible to JS
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"          # CSRF-hardening for cookies
app.config["SESSION_COOKIE_SECURE"] = False            # would be True behind HTTPS in production
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=15)  # 15-minute timeout

db.init_app(app)
csrf = CSRFProtect(app)

SESSION_TIMEOUT_MINUTES = 15


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def get_client_ip() -> str:
    return request.remote_addr or "unknown"


def current_user():
    """Re-validates the account against the database on every request
    (catches disabled accounts / stale sessions), and enforces the
    15-minute idle session timeout."""
    uid = session.get("user_id")
    if not uid:
        return None

    last_active_str = session.get("last_active")
    if last_active_str:
        last_active = datetime.fromisoformat(last_active_str)
        if datetime.utcnow() - last_active > timedelta(minutes=SESSION_TIMEOUT_MINUTES):
            session.clear()
            flash("Your session expired due to inactivity. Please log in again.", "warning")
            return None

    user = db.session.get(User, uid)
    if not user or not user.is_active:
        # Account disabled or deleted since login -> kill the session.
        session.clear()
        return None

    session["last_active"] = datetime.utcnow().isoformat()
    session.permanent = True
    return user


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user:
            return redirect(url_for("login"))
        return view(user, *args, **kwargs)
    return wrapped


def admin_required(view):
    """SECURE: server-side RBAC enforcement. The role is re-checked against
    the freshly-loaded database record on every request -- never trusted
    from client input or a stale session value."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user:
            return redirect(url_for("login"))
        if not user.is_admin():
            log_event(
                db.session, event_type="unauthorized_admin_access", result="failure",
                username=user.email, user_id=user.id, ip_address=get_client_ip(),
            )
            return redirect(url_for("access_denied"))
        return view(user, *args, **kwargs)
    return wrapped


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def home():
    return render_template("home.html", user=current_user())


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("employee_dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        password = form.password.data
        ip = get_client_ip()

        user = User.query.filter_by(email=email).first()

        # SECURE: generic error message regardless of whether the email
        # exists, to prevent user enumeration.
        generic_error = "Invalid email or password."

        if user is None:
            log_event(db.session, "login", "failure", username=email, ip_address=ip)
            flash(generic_error, "danger")
            return render_template("login.html", form=form)

        if user.is_locked():
            log_event(db.session, "account_lockout", "failure",
                      username=user.email, user_id=user.id, ip_address=ip)
            flash("This account is temporarily locked due to repeated failed "
                  "login attempts. Try again later or contact an administrator.", "danger")
            return render_template("login.html", form=form)

        if not user.is_active:
            log_event(db.session, "login", "failure",
                      username=user.email, user_id=user.id, ip_address=ip)
            flash(generic_error, "danger")
            return render_template("login.html", form=form)

        if user.check_password(password):
            user.register_successful_login()
            db.session.commit()

            # SECURE: regenerate session on login (mitigates session fixation).
            session.clear()
            session["user_id"] = user.id
            session["last_active"] = datetime.utcnow().isoformat()
            session.permanent = True

            log_event(db.session, "login", "success",
                      username=user.email, user_id=user.id, ip_address=ip)
            flash(f"Welcome back, {user.full_name}!", "success")
            return redirect(url_for("employee_dashboard"))
        else:
            user.register_failed_attempt()
            locked_now = user.is_locked()
            db.session.commit()

            log_event(db.session, "login", "failure",
                      username=user.email, user_id=user.id, ip_address=ip)
            if locked_now:
                log_event(db.session, "account_lockout", "failure",
                          username=user.email, user_id=user.id, ip_address=ip)
                flash("Too many failed attempts. This account is now locked "
                      "for 10 minutes.", "danger")
            else:
                flash(generic_error, "danger")

    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout(user):
    log_event(db.session, "logout", "success",
              username=user.email, user_id=user.id, ip_address=get_client_ip())
    session.clear()
    flash("You have been securely logged out.", "info")
    return redirect(url_for("home"))


@app.route("/dashboard")
@login_required
def employee_dashboard(user):
    return render_template("employee_dashboard.html", user=user)


@app.route("/admin")
@admin_required
def admin_dashboard(user):
    all_users = User.query.order_by(User.created_at).all()
    return render_template("admin_dashboard.html", user=user, all_users=all_users)


@app.route("/profile")
@login_required
def profile(user):
    return render_template("profile.html", user=user)


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password(user):
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not user.check_password(form.current_password.data):
            flash("Current password is incorrect.", "danger")
        else:
            user.set_password(form.new_password.data)
            db.session.commit()
            log_event(db.session, "password_change", "success",
                      username=user.email, user_id=user.id, ip_address=get_client_ip())
            flash("Password updated successfully.", "success")
            return redirect(url_for("profile"))

    return render_template("change_password.html", user=user, form=form)


@app.route("/users")
@admin_required
def user_management(user):
    all_users = User.query.order_by(User.created_at).all()
    form = EmptyForm()
    role_form = RoleChangeForm()
    return render_template(
        "user_management.html", user=user, all_users=all_users,
        form=form, role_form=role_form,
    )


@app.route("/users/<int:target_id>/toggle-active", methods=["POST"])
@admin_required
def toggle_active(user, target_id):
    form = EmptyForm()
    if not form.validate_on_submit():
        abort(400)

    target = db.session.get(User, target_id)
    if not target:
        abort(404)

    target.is_active = not target.is_active
    db.session.commit()

    log_event(
        db.session,
        event_type="account_enabled" if target.is_active else "account_disabled",
        result="success", username=target.email, user_id=target.id,
        ip_address=get_client_ip(),
    )
    flash(f"{'Enabled' if target.is_active else 'Disabled'} account for {target.email}.", "info")
    return redirect(url_for("user_management"))


@app.route("/users/<int:target_id>/unlock", methods=["POST"])
@admin_required
def unlock_account(user, target_id):
    form = EmptyForm()
    if not form.validate_on_submit():
        abort(400)

    target = db.session.get(User, target_id)
    if not target:
        abort(404)

    target.unlock()
    db.session.commit()

    log_event(db.session, "account_unlock", "success",
              username=target.email, user_id=target.id, ip_address=get_client_ip())
    flash(f"Unlocked account for {target.email}.", "info")
    return redirect(url_for("user_management"))


@app.route("/users/<int:target_id>/role", methods=["POST"])
@admin_required
def change_role(user, target_id):
    role_form = RoleChangeForm()
    if not role_form.validate_on_submit():
        abort(400)

    target = db.session.get(User, target_id)
    if not target:
        abort(404)

    old_role = target.role
    target.role = role_form.role.data
    db.session.commit()

    log_event(
        db.session, "role_change", "success", username=target.email, user_id=target.id,
        ip_address=get_client_ip(),
    )
    flash(f"Changed role for {target.email} from {old_role} to {target.role}.", "info")
    return redirect(url_for("user_management"))


@app.route("/audit-logs")
@admin_required
def audit_logs(user):
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(200).all()
    return render_template("audit_logs.html", user=user, logs=logs)


@app.route("/access-denied")
def access_denied():
    return render_template("access_denied.html", user=current_user())


@app.errorhandler(403)
def forbidden(e):
    return render_template("access_denied.html", user=current_user()), 403


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    # debug=False by default for the secure demo; enable manually if needed
    # for local development only.
    app.run(host="127.0.0.1", port=5001, debug=False)
