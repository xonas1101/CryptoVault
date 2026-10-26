"""Web interface on top of an unlocked Vault. Started by `python -m cryptovault`.

Nothing security-critical happens here. Access control, encryption and logging all
live in vault.py. This module turns HTTP requests into vault calls and renders pages.
"""
import io
import os
import secrets
import time
from datetime import datetime, time as dtime
from functools import wraps

from flask import Flask, abort, flash, redirect, render_template, request, send_file, session, url_for

from . import preview
from .crypto import CryptoError
from .vault import AccessDenied, PasswordRequired, QuorumRequired, Vault, VaultError

IDLE_TIMEOUT = 15 * 60
MAX_UPLOAD = 100 * 1024 * 1024


def create_app(vault: Vault):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.urandom(32),         # new on every start: restarting the server logs everyone out
        MAX_CONTENT_LENGTH=MAX_UPLOAD,
        SESSION_COOKIE_HTTPONLY=True,      # JavaScript can't read the cookie
        SESSION_COOKIE_SAMESITE="Strict",  # cookie is never sent on cross-site requests, which blocks CSRF
    )
    v = vault
    # ponytail: in-process session table, so this works with a single server process only
    # random token -> {"user", "seen", "me": the user's unsealed private keys, "keys": {file id: password-derived key}}
    sessions = {}

    def current():
        token = session.get("token")
        s = sessions.get(token)
        if s and time.time() - s["seen"] < IDLE_TIMEOUT:
            s["seen"] = time.time()
            return s["user"]
        sessions.pop(token, None)
        session.pop("token", None)  # not session.clear(): that would also wipe pending flash messages
        return None

    def start(user, password):
        token = secrets.token_urlsafe(32)  # fresh token on every login, which prevents session fixation
        # the private keys are unsealed with the login password and held only while the session lives
        sessions[token] = {"user": user, "seen": time.time(), "me": v.user_keys(user, password), "keys": {}}
        session["token"] = token

    def my_keys():
        return sessions[session["token"]]["me"]

    def key_for(fid):
        # ponytail: unlocked file keys live in server memory until logout or idle timeout, so each
        # preview image doesn't re-run scrypt; a per-file timeout if that's too generous
        return sessions[session["token"]]["keys"].get(fid)

    def home():
        return redirect(url_for("index"))

    def logged_in(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = current()
            if not user:
                flash("Please log in.", "error")
                return home()
            try:
                return fn(user, *args, **kwargs)
            except (VaultError, CryptoError) as e:
                flash(str(e), "error")
                return home()
        return wrapper

    @app.after_request
    def security_headers(resp):
        resp.headers["Cache-Control"] = "no-store"  # never cache decrypted content
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Content-Security-Policy"] = ("default-src 'none'; img-src 'self'; "
                                                   "style-src 'unsafe-inline'; form-action 'self'")
        return resp

    app.jinja_env.globals["LAYER_NAMES"] = {"system": "server key", "password": "password",
                                            "quorum": "approval quorum", "cascade": "double encryption", "lockdown": "lockdown"}

    @app.template_filter("when")
    def when(ts):
        return datetime.fromtimestamp(ts).strftime("%d %b %Y, %H:%M") if ts else "never"

    @app.template_filter("clock")
    def clock(ts):
        return datetime.fromtimestamp(ts).strftime("%H:%M")

    @app.template_filter("day")
    def day(ts):
        return datetime.fromtimestamp(ts).strftime("%d %b %Y") if ts else "no expiry"

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
        user = current()
        if not user:
            return render_template("login.html")
        mine, shared, broken, approvals = v.files_for(user)
        return render_template("dashboard.html", user=user, mine=mine, shared=shared, broken=broken,
                               approvals=approvals, fingerprint=v.fingerprint(user))

    @app.post("/login")
    def login():
        try:
            password = request.form.get("password", "")
            start(v.authenticate(request.form.get("email", ""), password), password)
        except AccessDenied:
            flash("Wrong email or password.", "error")
        return home()

    @app.post("/register")
    def register():
        password = request.form.get("password", "")
        if password != request.form.get("confirm"):
            flash("Passwords do not match.", "error")
            return home()
        try:
            start(v.register(request.form.get("email", ""), password), password)
            flash("Account created.", "ok")
        except VaultError as e:
            flash(str(e), "error")
        return home()

    @app.post("/logout")
    def logout():
        sessions.pop(session.pop("token", None), None)
        return home()

    @app.get("/watermark.png")
    @logged_in
    def watermark_tile(user):
        return send_file(io.BytesIO(preview.tile_png(user)), mimetype="image/png")

    # ---------- files ----------

    @app.post("/upload")
    @logged_in
    def upload(user):
        f = request.files.get("file")
        if not f or not f.filename:
            raise VaultError("choose a file first")
        password = request.form.get("password") or None
        if password != (request.form.get("confirm") or None):
            raise VaultError("the file passwords do not match")
        try:
            threshold = int(request.form.get("threshold") or 0)
            destroy_at = request.form.get("destroy_at")
            destroy_at = datetime.strptime(destroy_at, "%Y-%m-%dT%H:%M").timestamp() if destroy_at else None
        except ValueError:
            raise VaultError("invalid quorum size or self-destruct time")
        approvers = request.form.get("approvers", "").replace(",", " ").split()
        fid = v.store(user, f.filename, f.read(), request.form.getlist("layer"), password, signer=my_keys()["sign"],
                      approvers=approvers, threshold=threshold, destroy_at=destroy_at)
        flash(f"Locked {f.filename}. Share it below.", "ok")
        return redirect(url_for("file_page", fid=fid))

    @app.post("/open")
    @logged_in
    def open_locked(user):
        f = request.files.get("file")
        if not f or not f.filename:
            raise VaultError("choose a .cvault file first")
        return redirect(url_for("file_page", fid=v.resolve_locked(f.read(), user)))

    @app.get("/file/<fid>")
    @logged_in
    def file_page(user, fid):
        try:
            data, meta, perm = v.read(fid, user, "view", key_for(fid))
        except PasswordRequired as e:
            return render_template("unlock.html", user=user, fid=fid, message=str(e))
        except QuorumRequired as e:
            return render_template("unlock.html", user=user, fid=fid, message=str(e), quorum=e.status)
        k = preview.kind(meta["type"])
        text = data[:preview.MAX_TEXT * 4].decode("utf-8", "replace")[:preview.MAX_TEXT] if k == "text" else None
        try:
            pages = preview.page_count(data, k) if k in ("image", "pdf") else 0
        except Exception:  # an unreadable PDF just gets no preview
            k, pages = None, 0
        activity, broken_at = v.activity(fid, user) if perm == "owner" else ([], None)
        return render_template("file.html", user=user, fid=fid, meta=meta, perm=perm, kind=k, text=text,
                               pages=pages, activity=activity, log_broken_at=broken_at, info=v.inspect(fid, user),
                               fingerprint=v.fingerprint(meta["owner"]),
                               quorum=v.quorum_status(fid, meta) if "quorum" in meta else None)

    @app.post("/file/<fid>/unlock")
    @logged_in
    def unlock(user, fid):
        try:
            sessions[session["token"]]["keys"][fid] = v.unlock_file(fid, user, request.form.get("password", ""))
        except AccessDenied as e:
            flash(str(e), "error")
        return redirect(url_for("file_page", fid=fid))

    @app.post("/file/<fid>/approve")
    @logged_in
    def approve(user, fid):
        v.approve(fid, user, my_keys()["box"])
        flash(f"Approved for {v.approval_ttl // 60} minutes. Your share was released; it was never stored unencrypted.", "ok")
        return home()

    @app.get("/file/<fid>/page/<int:n>.png")
    @logged_in
    def page_image(user, fid, n):
        data, meta, _ = v.read(fid, user, None, key_for(fid))  # the view itself was already logged by file_page
        try:
            png = preview.render_page(data, preview.kind(meta["type"]), n, user)
        except Exception:
            abort(404)
        return send_file(io.BytesIO(png), mimetype="image/png")

    @app.get("/file/<fid>/download")
    @logged_in
    def download(user, fid):
        data, meta, _ = v.read(fid, user, "download", key_for(fid))
        return send_file(io.BytesIO(data), as_attachment=True, download_name=meta["name"],
                         mimetype="application/octet-stream")  # never rendered inline

    @app.get("/file/<fid>/locked")
    @logged_in
    def download_locked(user, fid):
        blob, meta = v.locked_copy(fid, user)
        return send_file(io.BytesIO(blob), as_attachment=True, download_name=meta["name"] + ".cvault",
                         mimetype="application/octet-stream")

    @app.post("/file/<fid>/share")
    @logged_in
    def share(user, fid):
        email = request.form.get("email", "")
        until = request.form.get("until")
        try:
            until = datetime.combine(datetime.strptime(until, "%Y-%m-%d").date(), dtime.max).timestamp() if until else None
        except ValueError:
            raise VaultError("invalid expiry date")
        v.share(fid, user, email, request.form.get("perm", "view"), until)
        flash(f"Shared with {email.strip().lower()}.", "ok")
        return redirect(url_for("file_page", fid=fid))

    @app.post("/file/<fid>/revoke")
    @logged_in
    def revoke(user, fid):
        email = request.form.get("email", "")
        v.revoke(fid, user, email)
        flash(f"Revoked {email}. Any locked copies they downloaded no longer open.", "ok")
        return redirect(url_for("file_page", fid=fid))

    @app.post("/file/<fid>/delete")
    @logged_in
    def delete(user, fid):
        v.delete(fid, user)
        flash("Key destroyed. Every copy of the file, locked copies and backups included, is now undecryptable noise.", "ok")
        return home()

    return app
