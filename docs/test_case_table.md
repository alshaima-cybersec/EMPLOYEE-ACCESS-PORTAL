# Test Case Table

All automated tests live in `secure_portal/tests/test_secure_portal.py` and run via `pytest`.
Manual/live verification was also performed against both running applications during
development (see command sequences in the README's Testing section).

| # | Test Case | Type | Target | Expected Result | Automated? |
|---|---|---|---|---|---|
| 1 | Correct employee login | Functional | Secure | HTTP 200, Employee Dashboard rendered | Yes (`test_correct_employee_login`) |
| 2 | Incorrect password | Functional | Secure | Generic "Invalid email or password" shown; not authenticated | Yes (`test_incorrect_password`) |
| 3 | Lockout after five failures | Security | Secure | Account locked after 5th failure; 6th attempt (even correct password) rejected with lockout message | Yes (`test_lockout_after_five_failures`) |
| 4 | Weak password rejected | Security | Secure | Password not meeting complexity policy is rejected with a validation message | Yes (`test_weak_password_rejected`) |
| 5 | Strong password accepted | Functional | Secure | Password meeting policy is accepted and hash updates in DB | Yes (`test_strong_password_accepted`) |
| 6 | Employee blocked from admin route | Security | Secure | Employee visiting `/admin` is redirected to Access Denied, not the dashboard | Yes (`test_employee_blocked_from_admin_route`) |
| 7 | Administrator allowed into admin route | Functional | Secure | Admin visiting `/admin` receives HTTP 200 and sees the dashboard | Yes (`test_admin_allowed_into_admin_route`) |
| 8 | Disabled account blocked | Security | Secure | Login attempt for a disabled account fails with the generic error message | Yes (`test_disabled_account_blocked`) |
| 9 | Session timeout | Security | Secure | Session idle for >15 minutes is invalidated on next request; user redirected to login | Yes (`test_session_timeout`) |
| 10 | Audit log created (success) | Functional | Secure | Successful login creates an `AuditLog` row with `event_type='login'`, `result='success'` | Yes (`test_audit_log_created_on_login`) |
| 11 | Audit log created (failure) | Functional | Secure | Failed login creates an `AuditLog` row with `result='failure'` | Yes (`test_audit_log_created_on_failed_login`) |
| 12 | Password stored as a hash | Security | Secure | `User.password_hash` is never equal to the plaintext password and uses a recognized Werkzeug hash prefix | Yes (`test_password_stored_as_hash`) |
| 13 | Logout invalidates the session | Security | Secure | After logout, a request to a protected route redirects to the login page | Yes (`test_logout_invalidates_session`) |
| 14 | Broken access control demo | Security | Vulnerable | Employee visiting `/admin` receives HTTP 200 (unauthorized access succeeds) | Manual (live curl test; documented in README) |
| 15 | Unlimited login attempts demo | Security | Vulnerable | Repeated failed logins never lock the account | Manual |
| 16 | Weak password accepted demo | Security | Vulnerable | A one-character password is accepted on change-password | Manual |
| 17 | Missing audit log demo | Security | Vulnerable | `/audit-logs` always renders an empty table regardless of activity | Manual |

## Running the automated suite

```
cd secure_portal
venv\Scripts\activate
pytest -v
```

Expected output: `13 passed` (test case #10 and #11 above both live under the "audit log
created" requirement, split into two functions for clarity — 13 automated functions total).
