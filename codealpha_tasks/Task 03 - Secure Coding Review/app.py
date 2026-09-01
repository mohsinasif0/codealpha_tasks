"""
NotesApp - a small Flask notes manager.
(Deliberately written the way a rushed junior developer might write it,
for use as a Secure Code Review training target.)
"""

import os
import sqlite3
import hashlib
import pickle
import base64

from flask import (
    Flask, request, render_template, render_template_string,
    redirect, session, g, send_from_directory
)

app = Flask(__name__)

# --- VULN 1: Hardcoded secret key committed to source code ---
app.secret_key = "supersecret123"

DB_PATH = os.path.join(os.path.dirname(__file__), "notes.db")
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
    return g.db


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY, username TEXT, password TEXT, is_admin INTEGER DEFAULT 0)""")
    db.execute("""CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, body TEXT)""")
    # --- VULN 2: Weak password hashing (unsalted MD5) ---
    pw = hashlib.md5("password123".encode()).hexdigest()
    admin_pw = hashlib.md5("admin".encode()).hexdigest()
    db.execute("INSERT OR IGNORE INTO users (id, username, password, is_admin) VALUES (1, 'alice', ?, 0)", (pw,))
    db.execute("INSERT OR IGNORE INTO users (id, username, password, is_admin) VALUES (2, 'admin', ?, 1)", (admin_pw,))
    db.commit()
    db.close()


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        pw_hash = hashlib.md5(password.encode()).hexdigest()

        db = get_db()
        # --- VULN 3: SQL Injection (string formatting, not parameterized) ---
        query = "SELECT id, username, is_admin FROM users WHERE username = '%s' AND password = '%s'" % (username, pw_hash)
        cur = db.execute(query)
        user = cur.fetchone()

        if user:
            # --- VULN 4: No session regeneration on login (session fixation risk) ---
            session["user_id"] = user[0]
            session["username"] = user[1]
            session["is_admin"] = user[2]
            return redirect("/dashboard")
        else:
            # --- VULN 5: Verbose error leaks whether username exists ---
            return f"Login failed for user '{username}'. Check username/password.", 401

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/login")
    db = get_db()
    notes = db.execute("SELECT id, title FROM notes WHERE user_id = ?", (session["user_id"],)).fetchall()
    return render_template("dashboard.html", notes=notes, username=session["username"])


@app.route("/note/<int:note_id>")
def view_note(note_id):
    if "user_id" not in session:
        return redirect("/login")
    db = get_db()
    # --- VULN 6: IDOR - no check that this note belongs to session user ---
    note = db.execute("SELECT id, title, body FROM notes WHERE id = ?", (note_id,)).fetchone()
    if not note:
        return "Not found", 404
    # --- VULN 7: Stored XSS - note body rendered without escaping ---
    template = "<h2>{{ title }}</h2><div>" + note[2] + "</div>"
    return render_template_string(template, title=note[1])


@app.route("/note/new", methods=["GET", "POST"])
def new_note():
    if "user_id" not in session:
        return redirect("/login")
    if request.method == "POST":
        title = request.form["title"]
        body = request.form["body"]
        db = get_db()
        db.execute("INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)",
                   (session["user_id"], title, body))
        db.commit()
        # --- VULN 8: No CSRF protection on state-changing POST form ---
        return redirect("/dashboard")
    return render_template("new_note.html")


@app.route("/search")
def search():
    q = request.args.get("q", "")
    db = get_db()
    # --- VULN 9: SQL Injection via search (string concatenation) ---
    query = "SELECT id, title FROM notes WHERE title LIKE '%" + q + "%'"
    results = db.execute(query).fetchall()
    return render_template("search.html", results=results, q=q)


@app.route("/upload", methods=["POST"])
def upload():
    if "user_id" not in session:
        return redirect("/login")
    f = request.files["file"]
    # --- VULN 10: Unrestricted file upload, no extension/type check, path traversal via filename ---
    save_path = os.path.join(UPLOAD_DIR, f.filename)
    f.save(save_path)
    return redirect("/dashboard")


@app.route("/uploads/<path:filename>")
def get_upload(filename):
    # --- VULN 11: Path traversal - filename not sanitized before send_from_directory misuse ---
    return send_from_directory(UPLOAD_DIR, filename)


@app.route("/import", methods=["POST"])
def import_notes():
    if "user_id" not in session:
        return redirect("/login")
    # --- VULN 12: Insecure deserialization - pickle.loads on user-controlled data ---
    data = base64.b64decode(request.form["data"])
    notes = pickle.loads(data)
    db = get_db()
    for n in notes:
        db.execute("INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)",
                   (session["user_id"], n["title"], n["body"]))
    db.commit()
    return redirect("/dashboard")


@app.route("/admin/users")
def admin_users():
    # --- VULN 13: Broken access control - checks session exists but not is_admin ---
    if "user_id" not in session:
        return redirect("/login")
    db = get_db()
    users = db.execute("SELECT id, username, is_admin FROM users").fetchall()
    return render_template("admin_users.html", users=users)


if __name__ == "__main__":
    init_db()
    # --- VULN 14: Debug mode + binds to all interfaces in what looks like prod entrypoint ---
    app.run(host="0.0.0.0", port=5000, debug=True)
