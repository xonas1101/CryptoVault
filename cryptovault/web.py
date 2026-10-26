"""Web interface. Start with `python -m cryptovault serve`, then open http://127.0.0.1:8000

This is only a front end. All security comes from vault.py and crypto.py, so the CLI
and the web UI work on the same vault. After login, the server keeps the session's
password in memory only (never on disk, never in the cookie) so it can unlock the
user's keystore for each action. Logging out, or 15 minutes of inactivity, forgets it.
"""
import io
import os
import secrets
import time
from datetime import datetime
from functools import wraps

from flask import Flask, flash, redirect, render_template, request, send_file, session, url_for

from .crypto import CryptoError
from .vault import Vault, VaultError

IDLE_TIMEOUT = 15 * 60
MAX_UPLOAD = 100 * 1024 * 1024


def create_app(vault_dir):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.urandom(32),         # new on every start: restarting the server logs everyone out
        MAX_CONTENT_LENGTH=MAX_UPLOAD,
        SESSION_COOKIE_HTTPONLY=True,      # JavaScript can't read the cookie
        SESSION_COOKIE_SAMESITE="Strict",  # cookie is never sent on cross-site requests, which blocks CSRF
    )
    v = Vault(vault_dir)
    # ponytail: in-process session table, so this works with a single server process only
    sessions = {}  # random token -> {"user", "password", "seen"}

    def current():
        token = session.get("token")
        s = sessions.get(token)
        if s and time.time() - s["seen"] < IDLE_TIMEOUT:
            s["seen"] = time.time()
            return s
        sessions.pop(token, None)
        session.pop("token", None)  # not session.clear(): that would also wipe pending flash messages
        return None

    def start(user, password):
        token = secrets.token_urlsafe(32)  # fresh token on every login, which prevents session fixation
        sessions[token] = {"user": user, "password": password, "seen": time.time()}
        session["token"] = token

    def home():
        return redirect(url_for("index"))

    def logged_in(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            s = current()
            if not s:
                flash("Please log in.", "error")
                return home()
            try:
                return fn(s, *args, **kwargs)
            except (VaultError, CryptoError) as e:
                flash(str(e), "error")
                return home()
        return wrapper

    @app.after_request
    def security_headers(resp):
        resp.headers["Cache-Control"] = "no-store"  # never cache decrypted files or file lists
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'"
        return resp

    @app.template_filter("when")
    def when(ts):
        return datetime.fromtimestamp(ts).strftime("%d %b %Y, %H:%M")

    @app.template_filter("size")
    def size(n):
        for unit in ("B", "KB", "MB"):
            if n < 1024:
                return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} GB"

    # ---------- account ----------

    @app.get("/")
    def index():
        s = current()
        if not s:
            return render_template("login.html")
        try:
            files = v.ls(s["user"], s["password"])
        except (VaultError, CryptoError) as e:
            files = []
            flash(str(e), "error")
        others = [u for u in v.users() if u != s["user"]]
        return render_template("dashboard.html", user=s["user"], fingerprint=v.fingerprint(s["user"]),
                               files=files, others=others)

    @app.post("/login")
    def login():
        user, pw = request.form.get("user", "").strip().lower(), request.form.get("password", "")
        try:
            v.unlock(user, pw)
        except (VaultError, CryptoError):
            flash("Wrong user name or password.", "error")  # same message either way, so user names can't be probed
            return home()
        start(user, pw)
        return home()

    @app.post("/register")
    def register():
        user, pw = request.form.get("user", "").strip().lower(), request.form.get("password", "")
        if pw != request.form.get("confirm"):
            flash("Passwords do not match.", "error")
            return home()
        try:
            fp = v.add_user(user, pw)
        except VaultError as e:
            flash(str(e), "error")
            return home()
        start(user, pw)
        flash(f"Account created. Your key fingerprint is {fp}", "ok")
        return home()

    @app.post("/logout")
    def logout():
        sessions.pop(session.pop("token", None), None)
        return home()

    # ---------- files ----------

    @app.post("/upload")
    @logged_in
    def upload(s):
        f = request.files.get("file")
        if not f or not f.filename:
            raise VaultError("choose a file first")
        v.put_data(f.filename, f.read(), s["user"], s["password"], request.form.getlist("share"))
        flash(f"Locked {f.filename}.", "ok")
        return home()

    @app.get("/file/<fid>/download")
    @logged_in
    def download(s, fid):
        data, meta = v.read(fid, s["user"], s["password"])
        return send_file(io.BytesIO(data), as_attachment=True, download_name=meta["name"])

    @app.get("/file/<fid>/inspect")
    @logged_in
    def inspect(s, fid):
        return render_template("inspect.html", user=s["user"], fid=fid, info=v.inspect(fid, s["user"], s["password"]))

    @app.post("/file/<fid>/verify")
    @logged_in
    def verify(s, fid):
        meta = v.verify(fid, s["user"], s["password"])
        flash(f"{meta['name']}: every segment authentic, SHA-256 matches, signed by {meta['owner']}.", "ok")
        return home()

    @app.post("/file/<fid>/share")
    @logged_in
    def share(s, fid):
        targets = request.form.getlist("users")
        v.share(fid, s["user"], s["password"], targets)
        flash(f"Shared with {', '.join(targets)}." if targets else "Nobody selected.", "ok")
        return home()

    @app.post("/file/<fid>/revoke")
    @logged_in
    def revoke(s, fid):
        targets = request.form.getlist("users")
        v.revoke(fid, s["user"], s["password"], targets)
        flash(f"Revoked {', '.join(targets)}. The file was re-encrypted under a fresh key.", "ok")
        return home()

    @app.post("/file/<fid>/delete")
    @logged_in
    def delete(s, fid):
        v.remove(fid, s["user"], s["password"])
        flash("File deleted.", "ok")
        return home()

    return app
