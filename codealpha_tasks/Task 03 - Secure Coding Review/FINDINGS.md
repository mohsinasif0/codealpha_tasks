# Secure Coding Review — NotesApp (Flask/Python)

**Prepared for:** CodeAlpha Cybersecurity Internship — Task 3
**Application audited:** NotesApp, a Flask-based notes manager (Python)
**Review type:** Manual source code review + tool-assisted static analysis
**Author:** Mohsin Asif
**Date:** 9/2/2026

---

## 1. Overview

For this task I audited a small Flask web application called NotesApp — a notes manager with user login, note creation/viewing, file upload, search, and a basic admin panel. I chose to work against a self-contained Flask CRUD app rather than a large existing open-source project, since it gave me a realistic amount of attack surface (authentication, database queries, file handling, session management) without the review taking weeks.

I used two approaches, as required by the task brief:

1. **Static analysis** — I wrote a small Python script that walks the code's abstract syntax tree (the same core technique used by tools like Bandit) to flag dangerous function calls and risky patterns automatically.
2. **Manual review** — I went through the application route by route and traced how user input flows through the code, since a lot of the more serious bugs here are logic flaws that a scanner can't catch.

Between the two methods I found **14 distinct issues**. Four of them (two SQL injection points and two broken access control issues) were only caught during manual review — the scanner missed them because they involve logic gaps rather than obviously dangerous syntax. I think that gap is actually one of the more useful takeaways from this exercise: automated tools are good at catching "this function call is inherently risky," but bad at catching "this code forgot to check something." A real audit needs both.

I also didn't just read the code — I stood the app up locally and actually exploited the two most serious findings (the login SQL injection and the note IDOR) to confirm they're real and reproducible, not theoretical. Screenshots/output for both are included below.

---

## 2. Summary of Findings

| # | Vulnerability | OWASP Category | Severity | Location |
|---|---|---|---|---|
| 1 | Hardcoded Flask secret key | A02 – Cryptographic Failures | High | `app.py:21` |
| 2 | Weak password hashing (unsalted MD5) | A02 – Cryptographic Failures | Medium-High | `app.py:40-53` |
| 3 | SQL injection — login | A03 – Injection | Critical | `app.py:43` |
| 4 | SQL injection — search | A03 – Injection | Critical | `app.py:118` |
| 5 | Session fixation risk (no session rotation on login) | A07 – Auth Failures | Medium | `app.py`, `/login` |
| 6 | Verbose login error (user enumeration) | A07 – Auth Failures | Low-Medium | `app.py`, `/login` |
| 7 | IDOR — any user can read any note | A01 – Broken Access Control | High | `app.py`, `/note/<id>` |
| 8 | Stored XSS in note view | A03 – Injection | High | `app.py`, `/note/<id>` |
| 9 | Missing CSRF protection | A01 – Broken Access Control | Medium | All POST routes |
| 10 | Unrestricted file upload | A04 – Insecure Design | Medium-High | `app.py`, `/upload` |
| 11 | Path traversal exposure on file download | A01 – Broken Access Control | High (paired with #10) | `app.py`, `/uploads/<filename>` |
| 12 | Insecure deserialization (`pickle.loads`) | A08 – Data Integrity Failures | Critical | `app.py`, `/import` |
| 13 | Broken access control — admin panel | A01 – Broken Access Control | High | `app.py`, `/admin/users` |
| 14 | Debug mode + bind to all interfaces | A05 – Security Misconfiguration | Medium / Low | `app.py`, entrypoint |

---

## 3. Tool-Assisted Static Analysis

I didn't have Bandit available in my environment, so I wrote a small scanner (`mini_sast.py`) that parses the code with Python's `ast` module and flags known-risky patterns — hardcoded secrets, `pickle.loads`, MD5 usage, `debug=True`, and a few others. It's a simplified version of what tools like Bandit do under the hood.

Running it against `app.py` produced 10 findings:

```
[HIGH  ] app.py:14   render_template_string() building HTML with unescaped user content -> XSS risk
[HIGH  ] app.py:21   Flask secret_key is a hardcoded string literal -> session/cookie forgery risk
[MEDIUM] app.py:40   MD5 used for password hashing -> not memory-hard, no salt
[MEDIUM] app.py:41   MD5 used for password hashing -> not memory-hard, no salt
[MEDIUM] app.py:53   MD5 used for password hashing -> not memory-hard, no salt
[HIGH  ] app.py:94   render_template_string() building HTML with unescaped user content -> XSS risk
[MEDIUM] app.py:130  Uploaded file saved using client-supplied filename without validation
[HIGH  ] app.py:146  pickle.loads() on data that may originate from user input -> RCE risk
[MEDIUM] app.py:168  Flask app run with debug=True -> exposes interactive debugger
[LOW   ] app.py:168  App binds to 0.0.0.0 -> exposed on all network interfaces
Total findings: 10
```

The four issues it missed (SQL injection x2, IDOR, admin access control) are the ones covered in detail below — every one of them comes down to the query or check being built correctly in isolation, but wrong in context, which static pattern-matching just isn't built to notice.

---

## 4. Detailed Findings

### 4.1 Hardcoded Secret Key
**Severity:** High
**Location:** `app.py`, line 21

```python
app.secret_key = "supersecret123"
```

Flask signs session cookies using this key so users can't tamper with their own session contents. Having it as a plaintext literal in the source means anyone with source access — or anyone who finds it if the repo is ever pushed public, which happens constantly with real projects — can forge valid, signed sessions for any account, admin included.

**Remediation:** Load the key from an environment variable or secrets manager at startup, generated randomly and never committed to version control:
```python
app.secret_key = os.environ["FLASK_SECRET_KEY"]
```

---

### 4.2 Weak Password Hashing
**Severity:** Medium-High
**Location:** `app.py`, lines 40, 41, 53

```python
pw = hashlib.md5("password123".encode()).hexdigest()
```

MD5 is fast and unsalted here, which is the opposite of what you want in a password hash. It was built for checksums, not credential storage — modern hardware can attempt billions of MD5 guesses per second, and rainbow tables covering common passwords are widely available, so cracking a leaked hash back to plaintext is close to instant for anything not fairly random.

**Remediation:** Use a slow, salted, purpose-built algorithm:
```python
from werkzeug.security import generate_password_hash, check_password_hash
pw_hash = generate_password_hash(password)
check_password_hash(stored_hash, submitted_password)
```

---

### 4.3 SQL Injection — Login Bypass
**Severity:** Critical
**Location:** `app.py`, line 43

```python
query = "SELECT id, username, is_admin FROM users WHERE username = '%s' AND password = '%s'" % (username, pw_hash)
```

User input is spliced directly into the SQL string. I tested this against the running app: submitting username `admin' -- ` with any password logs you in as `admin`, because `--` starts a SQL comment and erases the password check entirely from the executed query. No credentials required.

**Proof of concept (tested live, both via curl and browser):**
```
POST /login
username=admin' -- 
password=anything_at_all

Result: 302 redirect to /dashboard, authenticated as admin
```

**Remediation:** Parameterized queries, always:
```python
cur = db.execute("SELECT id, username, is_admin FROM users WHERE username = ? AND password = ?", (username, pw_hash))
```

---

### 4.4 SQL Injection — Search
**Severity:** Critical
**Location:** `app.py`, line 118

```python
query = "SELECT id, title FROM notes WHERE title LIKE '%" + q + "%'"
```

Same root cause as 4.3, different endpoint. The search field is concatenated straight into the query, so it's exploitable for both data extraction (via `UNION SELECT`) and potentially blind boolean-based injection depending on how results are displayed.

**Remediation:** Same fix — bind the parameter instead of concatenating:
```python
db.execute("SELECT id, title FROM notes WHERE title LIKE ?", ("%" + q + "%",))
```

---

### 4.5 Session Fixation Risk
**Severity:** Medium
**Location:** `app.py`, `/login`

The session dictionary is populated directly on successful login without first invalidating/rotating any pre-existing session identifier. If an attacker can plant a known session ID on a victim before they log in, that same ID could remain valid — and now attacker-known — after authentication.

**Remediation:** Regenerate the session on login (clear and repopulate), or adopt `flask-login`, which handles this correctly out of the box.

---

### 4.6 Verbose Login Error / User Enumeration
**Severity:** Low-Medium
**Location:** `app.py`, `/login`

```python
return f"Login failed for user '{username}'. Check username/password.", 401
```

Reflecting the submitted username back doesn't leak much on its own here since the message is the same either way, but it's still not a great habit — it's the kind of small inconsistency that, combined with timing differences or future code changes, tends to leak whether a username exists.

**Remediation:** Always return a generic, identical message: `"Invalid username or password."` Don't reflect submitted input back into error responses.

---

### 4.7 IDOR — Unauthorized Note Access
**Severity:** High
**Location:** `app.py`, `/note/<id>`

```python
note = db.execute("SELECT id, title, body FROM notes WHERE id = ?", (note_id,)).fetchone()
```

There's no check that the note belongs to whoever's logged in — just that a note with that ID exists. I confirmed this live: I created a note as one user, then, logged in as a completely different account, requested `/note/1` directly and read the private note contents without any authorization error. In a real deployment an attacker could just iterate note IDs and harvest every user's data.

**Remediation:** Scope the query to the current session's user:
```python
note = db.execute("SELECT id, title, body FROM notes WHERE id = ? AND user_id = ?", (note_id, session["user_id"])).fetchone()
```
Return 404 rather than 403 for someone else's note, so you're not even confirming the ID exists.

---

### 4.8 Stored XSS in Note View
**Severity:** High
**Location:** `app.py`, `/note/<id>`

```python
template = "<h2>{{ title }}</h2><div>" + note[2] + "</div>"
return render_template_string(template, title=note[1])
```

Jinja2 auto-escapes values passed in as template variables, but here the note body is concatenated straight into the template *source* before rendering — so it never goes through escaping at all. A note body containing a `<script>` tag would execute in the browser of anyone who views it, including an admin, which could be used to steal session cookies or perform actions as that user.

**Remediation:** Never build templates via string concatenation with user data — pass everything as a variable so Jinja2 escapes it automatically:
```python
return render_template("view_note.html", title=note[1], body=note[2])
```

---

### 4.9 Missing CSRF Protection
**Severity:** Medium
**Location:** All state-changing POST routes (`/note/new`, `/upload`, `/import`)

None of the forms include or validate an anti-CSRF token. A malicious page could host a hidden auto-submitting form targeting these endpoints; if a logged-in user simply visits that page, their browser will attach their session cookie automatically, letting the attacker's page perform actions as that user without their knowledge.

**Remediation:** Add `Flask-WTF`'s CSRF protection app-wide:
```python
from flask_wtf import CSRFProtect
CSRFProtect(app)
```

---

### 4.10 Unrestricted File Upload
**Severity:** Medium-High
**Location:** `app.py`, `/upload`

```python
save_path = os.path.join(UPLOAD_DIR, f.filename)
f.save(save_path)
```

No extension whitelist, size limit, or filename sanitization. The client fully controls the saved filename, which also feeds into the path traversal issue below.

**Remediation:**
```python
from werkzeug.utils import secure_filename
ALLOWED = {"txt", "pdf", "png", "jpg"}
filename = secure_filename(f.filename)
if filename.rsplit(".", 1)[-1].lower() not in ALLOWED:
    return "Unsupported file type", 400
f.save(os.path.join(UPLOAD_DIR, filename))
```

---

### 4.11 Path Traversal Exposure
**Severity:** High when paired with 4.10
**Location:** `app.py`, `/uploads/<path:filename>`

Because upload never sanitizes filenames, a crafted filename at upload time could attempt to write outside the intended directory, and the download route would then serve it back. Flask's `send_from_directory` does include some built-in path-traversal protection, so this is a case where the real fix is upstream — sanitizing at upload time — rather than the download route itself.

**Remediation:** Fix 4.10; treat this as confirmation that a single control (Flask's built-in path resolution) shouldn't be your only line of defense.

---

### 4.12 Insecure Deserialization
**Severity:** Critical
**Location:** `app.py`, `/import`

```python
data = base64.b64decode(request.form["data"])
notes = pickle.loads(data)
```

`pickle` can execute arbitrary code during deserialization — a crafted payload here doesn't need to exploit anything else, it can run OS commands the moment `pickle.loads()` is called. This is a direct path to remote code execution and is the single most severe finding in this review.

**Remediation:** Never deserialize untrusted data with `pickle`. Use a data-only format:
```python
import json
notes = json.loads(base64.b64decode(request.form["data"]))
```

---

### 4.13 Broken Access Control — Admin Panel
**Severity:** High
**Location:** `app.py`, `/admin/users`

```python
if "user_id" not in session:
    return redirect("/login")
```

This checks that someone is authenticated, but never checks whether they're authorized as an admin. Any logged-in user — including a freshly registered, zero-privilege account — can browse straight to the admin user list.

**Remediation:** Enforce role checks explicitly, ideally via a reusable decorator:
```python
def admin_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not session.get("is_admin"):
            return "Forbidden", 403
        return f(*a, **kw)
    return wrapper
```

---

### 4.14 Debug Mode Enabled + Bound to All Interfaces
**Severity:** Medium / Low
**Location:** `app.py`, entrypoint

```python
app.run(host="0.0.0.0", port=5000, debug=True)
```

I saw this one first-hand — running the app locally and triggering an unrelated error (a missing template) produced a full stack trace with the exact file path, line number, and surrounding source code, plus an interactive debugger PIN. With `debug=True`, that debugger allows arbitrary code execution to anyone who can reach it. Combined with `host="0.0.0.0"`, the app is reachable from every device on the local network, not just the machine running it — during testing my own app was visible at my LAN IP address.

**Remediation:** `debug=False` outside local development, bind to `127.0.0.1` for local testing, and use a production WSGI server (Gunicorn/uWSGI) behind a reverse proxy for anything beyond that.

---

## 5. General Recommendations

A few patterns came up repeatedly enough that they're worth calling out separately from the individual fixes above:

- **Never build SQL, HTML, or shell commands via string concatenation with user input.** Every injection-class bug in this app (SQLi x2, XSS, and arguably the deserialization issue) traces back to this one habit. Parameterized queries and template variables exist specifically to avoid it.
- **Authentication is not authorization.** Several bugs here (`/note/<id>`, `/admin/users`) correctly check that a user is logged in but never check what that user is allowed to do. These two checks need to be treated as separate steps every time.
- **Don't trust client-supplied data for anything security-relevant** — filenames, serialized objects, or session state included.
- **Secrets don't belong in source code**, ever, even for a small internal tool. Environment variables or a secrets manager cost nothing extra and remove an entire class of risk.
- **Debug tooling should never ship with a deployment.** It's fine locally; it's a severity multiplier for everything else once exposed.

---

## 6. Conclusion

This review turned up 14 issues spanning most of the OWASP Top 10 — injection, broken access control, cryptographic failures, insecure design, and misconfiguration all showed up in a codebase of a few hundred lines, which says more about how easy these mistakes are to make than anything else. Two of the findings (the login SQL injection and the note IDOR) were exploited live against the running application to confirm real impact rather than just theoretical risk.

The pattern I'd draw out for future reviews: automated scanning found the "obviously dangerous function" bugs quickly, but the highest-severity access-control bugs only surfaced from manually tracing how each route treats user input and session state. Neither approach on its own would have caught everything here — which is really the main lesson of this task.
