# CodeAlpha_SecureCodingReview
A secure code review of a small Flask/Python web application, developed as part of the CodeAlpha Cybersecurity Internship.

## Overview
This project is a manual + tool-assisted security audit of **NotesApp**, a self-contained Flask notes manager built specifically as the audit target (login, note CRUD, file upload, search, admin panel). Rather than reviewing a large existing open-source project, I built a small realistic app and audited it end-to-end so I could go deep on every route rather than surface-level on a huge codebase.

The review found **14 vulnerabilities** spanning most of the OWASP Top 10 — SQL injection, broken access control, stored XSS, insecure deserialization, weak cryptography, and security misconfiguration. Two of the most severe findings (the login SQL injection and an IDOR on note access) were exploited live against the running app to confirm real impact, not just theoretical risk.

Building this helped me understand how vulnerabilities actually surface in real code — how a single string-concatenated SQL query becomes a full authentication bypass, why "logged in" and "authorized" are two different checks that both need to exist, and why automated scanners catch some bug classes well and completely miss others.

## How It Works
1. **Static analysis** — `mini_sast.py` walks the target app's code using Python's `ast` module (the same core technique tools like Bandit use) and flags known-risky patterns: hardcoded secrets, weak hashing, `pickle.loads()`, debug mode, and more.
2. **Manual review** — each Flask route in `app.py` was traced by hand, following user input from the request through to the database/filesystem/template layer, to catch logic flaws a scanner can't see (missing ownership checks, missing role checks, etc.).
3. **Live exploitation** — the app was actually run and attacked to confirm two of the critical findings work in practice: a SQL injection login bypass and an IDOR that exposes another user's private notes.
4. Findings were mapped to **OWASP Top 10 (2021)** categories, rated by severity, and documented with concrete remediation code.

## Usage
### Install dependencies
```bash
pip install flask
```

### Run the vulnerable target app
```bash
cd app
python3 app.py
```
> The app starts on `http://127.0.0.1:5000` with two seeded users: `alice` / `password123` and `admin` / `admin`.

### Run the static analysis scanner
```bash
python3 mini_sast.py app.py
```

### Reproduce the SQL injection login bypass
Go to `/login` and submit:
```
username: admin' -- 
password: anything
```
This logs you in as `admin` with no valid password, since `--` comments out the rest of the SQL query.

### Reproduce the IDOR
Log in as any user, create a note, note its ID, then log in as a **different** user and visit `/note/<that id>` directly — the note loads with no ownership check.

## Sample Output
```
=== mini_sast scan report: app.py ===

[HIGH  ] app.py:14   render_template_string() building HTML with unescaped user content -> XSS risk
[HIGH  ] app.py:21   Flask secret_key is a hardcoded string literal -> session/cookie forgery risk
[MEDIUM] app.py:40   MD5 used for password hashing -> not memory-hard, no salt
[HIGH  ] app.py:146  pickle.loads() on data that may originate from user input -> RCE risk
[MEDIUM] app.py:168  Flask app run with debug=True -> exposes interactive debugger
[LOW   ] app.py:168  App binds to 0.0.0.0 -> exposed on all network interfaces

Total findings: 10
```

## Findings Summary

| # | Vulnerability | OWASP Category | Severity |
|---|---|---|---|
| 1 | Hardcoded Flask secret key | A02 – Cryptographic Failures | High |
| 2 | Weak password hashing (unsalted MD5) | A02 – Cryptographic Failures | Medium-High |
| 3 | SQL injection — login | A03 – Injection | Critical |
| 4 | SQL injection — search | A03 – Injection | Critical |
| 5 | Session fixation risk | A07 – Auth Failures | Medium |
| 6 | Verbose login error (user enumeration) | A07 – Auth Failures | Low-Medium |
| 7 | IDOR — any user can read any note | A01 – Broken Access Control | High |
| 8 | Stored XSS in note view | A03 – Injection | High |
| 9 | Missing CSRF protection | A01 – Broken Access Control | Medium |
| 10 | Unrestricted file upload | A04 – Insecure Design | Medium-High |
| 11 | Path traversal exposure on file download | A01 – Broken Access Control | High |
| 12 | Insecure deserialization (`pickle.loads`) | A08 – Data Integrity Failures | Critical |
| 13 | Broken access control — admin panel | A01 – Broken Access Control | High |
| 14 | Debug mode + bind to all interfaces | A05 – Security Misconfiguration | Medium / Low |

Full detail on every finding — exact code, exploitation steps, and remediation — is in [`FINDINGS.md`](./FINDINGS.md).

## Key Concepts Demonstrated
- Manual secure code review across authentication, session management, database access, file handling, and deserialization
- Tool-assisted static analysis (AST-based pattern scanning, Bandit-style)
- Practical exploitation of SQL injection and IDOR against a live app to confirm real impact
- Mapping findings to the OWASP Top 10 (2021)
- Understanding where static analysis tools succeed (dangerous function calls) versus where they fail (missing authorization logic)

## Legal & Ethical Notice
NotesApp is **intentionally vulnerable** and was built solely as a training target for this exercise — it is not a real application and should never be deployed or exposed on a live network. All testing and exploitation shown here was performed against a local instance I built and controlled. Never attempt these techniques against systems you don't own or have explicit written permission to test.

## Built With
- Python 3
- [Flask](https://flask.palletsprojects.com/)
- SQLite
- Python `ast` module (custom static analyzer)

## About This Project
Developed as **Task 03: Secure Coding Review** for the CodeAlpha Cybersecurity Internship.
