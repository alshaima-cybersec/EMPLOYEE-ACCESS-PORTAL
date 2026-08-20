# Vulnerability Assessment and Secure Refactoring of an Enterprise Employee Access Portal

A university cybersecurity group project. Two versions of the same Employee Access Portal are
provided:

- **`vulnerable_portal/`** — intentionally demonstrates six specific security weaknesses.
- **`secure_portal/`** — the same application, refactored to mitigate each weakness.

Focus areas: **weak password storage, weak password policy, broken access control, unlimited
failed login attempts, insecure session handling, and missing audit logging.** SQL injection and
XSS are explicitly out of scope (see `docs/stride_threat_model.md` for a note on why the chosen
frameworks provide baseline protection against those classes anyway).

## ⚠️ Ethical and Localhost-Only Warning

**Both applications are for local, offline classroom use only.**

- Do not deploy either application to a public server or expose it to the internet.
- Both apps use entirely fictional demonstration data and demo credentials.
- The `vulnerable_portal` intentionally contains security weaknesses. Do not reuse its code
  patterns (password hashing, access control, session handling) in any real application.
- No destructive functionality, malware, or remote-exploitation tooling is included anywhere in
  this repository.
- Change the demo passwords immediately if you repurpose the secure version beyond this
  assignment.

## Project Structure

```
employee-access-portal/
├── README.md                          <- you are here
├── .gitignore
├── vulnerable_portal/
│   ├── app.py
│   ├── models.py
│   ├── seed_db.py
│   ├── requirements.txt
│   ├── .env.example
│   ├── static/css/style.css
│   ├── templates/                     (10 pages, warning banner on every page)
│   └── instance/                      (SQLite DB created at runtime, gitignored)
├── secure_portal/
│   ├── app.py
│   ├── models.py
│   ├── forms.py
│   ├── seed_db.py
│   ├── requirements.txt
│   ├── .env.example
│   ├── static/css/style.css
│   ├── templates/                     (10 pages, info banner on every page)
│   ├── tests/test_secure_portal.py    (13 automated pytest cases)
│   └── instance/                      (SQLite DB created at runtime, gitignored)
└── docs/
    ├── vulnerability_assessment.md
    ├── stride_threat_model.md
    ├── test_case_table.md
    ├── architecture_vulnerable.mmd
    ├── architecture_secure.mmd
    └── demo_script.md
```

## Software Requirements

- Windows 10/11
- Python 3.10+ (tested with 3.12)
- pip
- A modern browser (Chrome, Edge, Firefox)

## Installation & Setup

Each portal is a fully independent Flask application with its own virtual environment, so they
can run simultaneously on different ports without interfering with each other.

### 1. Vulnerable Portal (port 5000)

```powershell
cd vulnerable_portal
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python seed_db.py
python app.py
```

Visit **http://127.0.0.1:5000**

### 2. Secure Portal (port 5001)

```powershell
cd secure_portal
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

copy .env.example .env
# Open .env and replace SECRET_KEY with a real random value, e.g.:
python -c "import secrets; print(secrets.token_hex(32))"

python seed_db.py
python app.py
```

Visit **http://127.0.0.1:5001**

> The secure app will not start meaningfully secure without a real `SECRET_KEY` in `.env` — a
> fallback development key is used only if `.env` is missing, and this is logged as a
> configuration warning you should not rely on.

## Demo Credentials

| Portal | Role | Email | Password |
|---|---|---|---|
| Vulnerable | Administrator | admin@example.com | `admin123` |
| Vulnerable | Employee | employee@example.com | `password` |
| Secure | Administrator | admin@example.com | `AdminPass!2026` |
| Secure | Employee | employee@example.com | `EmployeePass!2026` |

**These are demonstration credentials only.** In the secure app, change them immediately via the
Change Password page before using the application beyond this coursework demo.

## Running the Test Suite

```powershell
cd secure_portal
venv\Scripts\activate
pytest -v
```

Expected: `13 passed`. See `docs/test_case_table.md` for the full mapping of test cases to
requirements, including manual verification steps for the vulnerable app's weaknesses (which are
demonstrated by their presence, not caught by tests, since they're intentional).

## Before-and-After Security Comparison

| Area | Vulnerable Version | Secure Version |
|---|---|---|
| Password storage | Unsalted MD5 (`hashlib.md5`) | Salted Werkzeug hash (`generate_password_hash`) |
| Password policy | None (1-character password accepted) | 12+ chars, upper/lower/number/special required |
| Access control | Session-presence check only; role trusted from session | Server-side `@admin_required` decorator, role re-verified from DB every request |
| Login attempts | Unlimited | Locked after 5 failures for 10 minutes |
| Session handling | No timeout; `HttpOnly=False`; no regeneration on login | 15-minute idle timeout; `HttpOnly`/`SameSite=Lax`; session regenerated on login |
| Audit logging | Table exists, never written to | Every security event logged with user, timestamp, result, IP |
| CSRF protection | None; state changes via GET | Flask-WTF CSRF tokens on every form; state changes via POST |
| Error messages | Reveal whether an email exists | Always generic ("Invalid email or password") |
| Secret key | Hardcoded in source | Loaded from `.env`, excluded via `.gitignore` |

Full detail: `docs/vulnerability_assessment.md`. Threat-model view: `docs/stride_threat_model.md`.

## Architecture Diagrams

Mermaid source files are provided in `docs/architecture_vulnerable.mmd` and
`docs/architecture_secure.mmd`. Render them at https://mermaid.live, in any Markdown viewer with
Mermaid support (e.g. GitHub, Obsidian, VS Code with the Mermaid extension), or via the `mermaid`
CLI.

## Live Demo Script

See `docs/demo_script.md` for a five-minute walkthrough sequence covering broken access control,
lockout behavior, password policy, password storage, and audit logging — designed to be run with
both apps open side by side.

## Troubleshooting

| Issue | Likely Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: No module named 'flask'` | Virtual environment not activated, or dependencies not installed | Run `venv\Scripts\activate` then `pip install -r requirements.txt` |
| Secure app throws a CSRF error on every form submit | `SECRET_KEY` missing/changed between requests, or cookies blocked | Ensure `.env` exists with a stable `SECRET_KEY`; don't clear cookies mid-session |
| `sqlite3.OperationalError: no such table` | Database not seeded | Run `python seed_db.py` inside the relevant portal folder |
| Port already in use | Another process (or the other portal) is bound to that port | Vulnerable uses 5000, Secure uses 5001 — confirm nothing else is using those ports, or edit the `app.run(port=...)` line |
| Locked out of the secure demo account during testing | 5 failed attempts trigger a 10-minute lockout by design | Wait 10 minutes, or have another admin account use "Unlock" on the User Management page |
| Changes to `.env` not taking effect | Flask dev server needs a restart to reload `python-dotenv` values | Stop (`Ctrl+C`) and re-run `python app.py` |
| `pytest` can't find `app` module | Running pytest from the wrong directory | Run `pytest` from inside `secure_portal/`, not the repo root |

## Notes on Scope

This project is intentionally scoped to authentication, session, and access-control weaknesses
per the assignment brief. SQL injection and XSS were not implemented or tested, though both
frameworks' defaults (SQLAlchemy parameterized queries, Jinja2 auto-escaping) provide baseline
protection against them. No functionality beyond what's listed in the brief was added.
