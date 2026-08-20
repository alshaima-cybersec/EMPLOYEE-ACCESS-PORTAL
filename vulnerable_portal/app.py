"""
app.py -- VULNERABLE Employee Access Portal (Educational Demo)

Run LOCALLY ONLY. Do not deploy this application publicly. It intentionally
contains security weaknesses for a university cybersecurity course:

  1. Weak password storage (unsalted MD5)
  2. Weak / no password policy
  3. Broken access control (client-trusted role check, no server enforcement
     on the admin route beyond checking session presence)
  4. Unlimited failed login attempts (no lockout)
  5. Insecure session handling (no timeout, non-HttpOnly-only cookie config
     left at Flask defaults, session not regenerated/cleared robustly)
  6. Missing audit logging (no security events recorded)

Compare against ../secure_portal/app.py for the mitigated version.
"""
import os
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, session, flash

from models import db, User, AuditLog

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

# VULNERABLE: hardcoded, weak secret key committed to source.
app.config["SECRET_KEY"] = "vuln-portal-not-a-real-secret"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(
    BASE_DIR, "instance", "vulnerable.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# VULNERABLE: no PERMANENT_SESSION_LIFETIME set -> session persists
# indefinitely in the browser (cookie has no real expiry policy enforced
# server-side), and cookie flags are left at insecure defaults.
app.config["SESSION_COOKIE_HTTPONLY"] = False  # VULNERABLE: readable by JS
app.config["SESSION_COOKIE_SAMESITE"] = None   # VULNERABLE: no CSRF-ish protection

db.init_app(app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def current_user():
    """VULNERABLE: trusts a plain user_id from session with no re-validation
    of account status (disabled accounts can still act on stale sessions)."""
    uid = session.get("user_id")
    if not uid:
        return None
    return db.session.get(User, uid)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def home():
    return render_template("home.html", user=current_user())


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "")
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        # VULNERABLE: no lockout, no attempt counting, no delay/backoff.
        if user and user.check_password(password):
            # VULNERABLE: session not regenerated (session fixation risk);
            # no login timestamp / last-activity tracking for timeout.
            session["user_id"] = user.id
            session["role"] = user.role  # VULNERABLE: role trusted from session
            flash(f"Welcome back, {user.full_name}!", "success")
            return redirect(url_for("employee_dashboard"))
        else:
            # VULNERABLE: specific error message helps attackers enumerate
            # valid emails.
            if user is None:
                flash("No account found with that email.", "danger")
            else:
                flash("Incorrect password. Try again.", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    # VULNERABLE: session.clear() is used here, but there is no server-side
    # session store invalidation and no audit trail of the logout event.
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))


@app.route("/dashboard")
def employee_dashboard():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    return render_template("employee_dashboard.html", user=user)


@app.route("/admin")
def admin_dashboard():
    # VULNERABLE: BROKEN ACCESS CONTROL.
    # This route only checks that *some* user is logged in, not that they
    # hold the 'admin' role server-side -- and even that check is weak
    # because it trusts session['role'] which was set at login time and
    # never re-validated against the database. Any employee who guesses
    # or bookmarks this URL can reach it if session role tampering or a
    # stale role value occurs. For classroom demonstration this route
    # deliberately omits a proper `if not user.is_admin(): abort(403)`
    # server-side check on the fetched user object.
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    # NOTE: real RBAC check intentionally omitted here (see secure_portal).
    all_users = User.query.all()
    return render_template("admin_dashboard.html", user=user, all_users=all_users)


@app.route("/profile")
def profile():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    return render_template("profile.html", user=user)


@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        # VULNERABLE: no complexity requirements, no minimum length enforced.
        user.set_password(new_password)
        db.session.commit()
        flash("Password changed.", "success")
        return redirect(url_for("profile"))

    return render_template("change_password.html", user=user)


@app.route("/users")
def user_management():
    # VULNERABLE: same broken access control pattern as /admin.
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    all_users = User.query.all()
    return render_template("user_management.html", user=user, all_users=all_users)


@app.route("/users/<int:target_id>/toggle-active")
def toggle_active(target_id):
    # VULNERABLE: no admin check, no audit log entry, GET request performs
    # a state-changing action (no CSRF protection at all).
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    target = User.query.get_or_404(target_id)
    target.is_active = not target.is_active
    db.session.commit()
    flash(f"Toggled active status for {target.email}.", "info")
    return redirect(url_for("user_management"))


@app.route("/audit-logs")
def audit_logs():
    # VULNERABLE: table exists but is always empty -- no events are ever
    # written by this application (missing audit logging).
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template("audit_logs.html", user=user, logs=logs)


@app.route("/access-denied")
def access_denied():
    return render_template("access_denied.html")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    # VULNERABLE: debug=True in a "run locally" app is acceptable for this
    # course demo, but is flagged in the README as something to disable
    # outside of local educational use.
    app.run(host="127.0.0.1", port=5000, debug=True)
