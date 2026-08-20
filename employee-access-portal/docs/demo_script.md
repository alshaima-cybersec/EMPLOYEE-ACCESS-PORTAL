# Five-Minute Live Demo Sequence

Suggested flow for a classroom or grading demonstration. Run `vulnerable_portal` on port 5000
and `secure_portal` on port 5001 side by side (two terminals, two browser tabs).

## Setup (before the demo starts)

```
# Terminal 1
cd vulnerable_portal
venv\Scripts\activate
python seed_db.py
python app.py            # http://127.0.0.1:5000

# Terminal 2
cd secure_portal
venv\Scripts\activate
python seed_db.py
python app.py             # http://127.0.0.1:5001
```

## Minute 0:00 – 0:45 — Introduce the two apps

- Open both home pages side by side. Point out the red "Educational vulnerable version" banner
  vs. the green "Secure hardened version" banner.
- State the six weaknesses being demonstrated (weak password storage, weak password policy,
  broken access control, unlimited login attempts, insecure session handling, missing audit
  logging).

## Minute 0:45 – 1:45 — Broken access control (the headline demo)

1. On the **vulnerable** app, log in as `employee@example.com` / `password`.
2. Manually type `http://127.0.0.1:5000/admin` in the address bar.
3. **Result:** the Admin Dashboard loads — an employee reached admin-only functionality with no
   privilege check.
4. On the **secure** app, log in as `employee@example.com` / `EmployeePass!2026`.
5. Manually type `http://127.0.0.1:5001/admin`.
6. **Result:** redirected to Access Denied. Open the admin account's Audit Logs page afterward to
   show the `unauthorized_admin_access` event recorded with timestamp and IP.

## Minute 1:45 – 2:45 — Unlimited login attempts vs. lockout

1. On the **vulnerable** app, submit 6+ incorrect passwords for `admin@example.com`. Show that
   nothing blocks further attempts.
2. On the **secure** app, submit 5 incorrect passwords for `admin@example.com`. On the 5th
   failure, show the "account is now locked for 10 minutes" message. Attempt a 6th login with
   the *correct* password and show it is still rejected while locked.

## Minute 2:45 – 3:30 — Weak vs. strong password policy

1. On the **vulnerable** app, go to Change Password and set the password to a single character
   (`a`). Show it succeeds.
2. On the **secure** app, go to Change Password and attempt the same. Show the validation error
   listing the missing complexity requirements. Then submit a compliant password (e.g.
   `NewPass!2026xyz`) and show it succeeds.

## Minute 3:30 – 4:15 — Password storage

1. On the **vulnerable** app, visit the Profile page while logged in and point out the visible
   MD5 hash — explain it is unsalted and crackable via rainbow tables.
2. On the **secure** app, visit Profile and show that no hash is displayed, and mention it is a
   salted Werkzeug hash server-side.

## Minute 4:15 – 5:00 — Audit logging wrap-up

1. On the **vulnerable** app, visit Audit Logs — show it is permanently empty.
2. On the **secure** app, visit Audit Logs as admin — show the full trail of events generated
   during the demo (logins, failures, lockout, unauthorized access attempt, password change).
3. Close with a one-line summary: "Every weakness shown in the first app has a concrete,
   testable fix in the second, and all fixes are covered by the automated pytest suite."
