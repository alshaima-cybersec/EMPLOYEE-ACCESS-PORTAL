# STRIDE Threat Model

Threat modeling of the Employee Access Portal using the STRIDE framework. Each row maps a
threat category to a concrete scenario against this application, its status in the vulnerable
build, and the mitigation applied in the secure build.

| STRIDE Category | Threat Scenario | Present in Vulnerable Version? | Mitigation in Secure Version |
|---|---|---|---|
| **S**poofing | Attacker guesses/brute-forces credentials to impersonate a legitimate employee or admin | Yes — unlimited attempts, weak password policy, weak hashing make credential compromise easy | Strong password policy, salted hashing, account lockout after 5 failures, generic error messages prevent enumeration |
| **T**ampering | Attacker forges or replays a session cookie / manipulates client-side role data to escalate privileges | Yes — role trusted from session (`session['role']`) set at login, never re-checked against DB | Role re-validated from the database on every request via `@admin_required`; session regenerated on login (mitigates fixation) |
| **R**epudiation | A user denies performing a sensitive action (e.g., disabling another account, changing a role) because no record exists | Yes — no audit logging at all, so any action is deniable | Every sensitive action (login, logout, lockout, password change, role change, account enable/disable, unlock, unauthorized access) is logged with user, timestamp, result, and IP |
| **I**nformation Disclosure | Sensitive data (password hashes, account existence) is exposed to unauthorized parties or via error messages | Yes — profile page displays the stored MD5 hash; login errors reveal whether an email is registered | Password hash never displayed in the UI; login always returns a generic error regardless of cause |
| **D**enial of Service | Attacker exhausts login attempts against many accounts to lock out legitimate users, or session/DB resources are abused | Partially — no rate limiting in either version (out of scope for this assessment), but the vulnerable version's *lack* of lockout means brute-force can run indefinitely without even locking anyone out (a different DoS-adjacent risk: unbounded resource use from unthrottled auth attempts) | Lockout limits are scoped per-account (5 attempts / 10-minute cooldown) to balance brute-force resistance against self-inflicted DoS from an attacker deliberately locking out a target account (a known trade-off, noted in Troubleshooting) |
| **E**levation of Privilege | Employee reaches admin-only functionality (view all users, change roles, view audit logs) by navigating directly to the URL | Yes — this is the core "broken access control" demonstration; confirmed via live test (employee received HTTP 200 on `/admin`) | `@admin_required` decorator enforces server-side RBAC on `/admin`, `/users`, `/audit-logs`, and all account-management POST routes; confirmed via live test (employee receives redirect to Access Denied, HTTP 302) |

## Assets in scope

- Employee and administrator credentials (password hashes)
- Session tokens / cookies
- Role and account-status data (`is_active`, `role`)
- Audit trail integrity

## Out of scope (per project brief)

SQL injection and XSS are explicitly out of scope for this assessment; both applications use
Flask-SQLAlchemy's parameterized ORM queries and Jinja2's default auto-escaping, which provide
baseline protection against these classes regardless of the six focus vulnerabilities above.
