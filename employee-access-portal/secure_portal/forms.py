"""
forms.py -- Secure Portal

Flask-WTF forms provide CSRF protection automatically (via the hidden
csrf_token field rendered in each template) and centralize input
validation, including the password complexity policy.
"""
import re

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError

PASSWORD_MIN_LENGTH = 12


def validate_password_complexity(form, field):
    password = field.data or ""
    errors = []

    if len(password) < PASSWORD_MIN_LENGTH:
        errors.append(f"at least {PASSWORD_MIN_LENGTH} characters")
    if not re.search(r"[a-z]", password):
        errors.append("a lowercase letter")
    if not re.search(r"[A-Z]", password):
        errors.append("an uppercase letter")
    if not re.search(r"[0-9]", password):
        errors.append("a number")
    if not re.search(r"[^A-Za-z0-9]", password):
        errors.append("a special character")

    if errors:
        raise ValidationError("Password must contain " + ", ".join(errors) + ".")


class LoginForm(FlaskForm):
    email = StringField("Email address", validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("Current password", validators=[DataRequired()])
    new_password = PasswordField(
        "New password",
        validators=[DataRequired(), validate_password_complexity],
    )
    confirm_password = PasswordField(
        "Confirm new password",
        validators=[DataRequired(), EqualTo("new_password", message="Passwords must match.")],
    )
    submit = SubmitField("Update Password")


class RoleChangeForm(FlaskForm):
    role = SelectField("Role", choices=[("employee", "Employee"), ("admin", "Administrator")])
    submit = SubmitField("Update Role")


class EmptyForm(FlaskForm):
    """Used for CSRF-protected state-changing buttons (toggle active, unlock, etc.)."""
    submit = SubmitField("Confirm")
