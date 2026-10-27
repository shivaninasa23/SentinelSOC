import uuid
from functools import wraps
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, abort, g
from flask_wtf.csrf import generate_csrf
from .extensions import db
from .models import User
from .services import audit, ingest_event
from . import limiter

auth_bp = Blueprint("auth", __name__)

@auth_bp.before_app_request
def load_user():
    g.user = db.session.get(User, session.get("user_id")) if session.get("user_id") else None

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not g.user or not g.user.active: return redirect(url_for("auth.login"))
        return fn(*args, **kwargs)
    return wrapped

def roles_required(*roles):
    def deco(fn):
        @wraps(fn)
        @login_required
        def wrapped(*args, **kwargs):
            if g.user.role not in roles: abort(403)
            return fn(*args, **kwargs)
        return wrapped
    return deco

@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("8 per minute", methods=["POST"])
def login():
    if request.method == "POST":
        name = request.form.get("username", "")[:80]
        user = User.query.filter_by(username=name, active=True).first()
        ok = bool(user and user.check_password(request.form.get("password", "")))
        if not user:
            from werkzeug.security import check_password_hash
            check_password_hash("scrypt:32768:8:1$sentinelsoc$not-a-real-hash", request.form.get("password", ""))
        audit("auth.login.success" if ok else "auth.login.failure", name, user.id if ok else None, {"source_ip": request.remote_addr})
        db.session.commit()
        ingest_event({"event_type":"authentication","source_system":"sentinelsoc-auth","source_ip":request.remote_addr,
            "username":name or None,"outcome":"success" if ok else "failure","severity":"low",
            "description":"Application login succeeded" if ok else "Application login failed"})
        if ok:
            session.clear(); session["user_id"] = user.id; session["csrf_nonce"] = str(uuid.uuid4()); session.permanent = True
            # CSRFProtect cached the pre-login token on this request's `g`.
            # Clear that cache so a fresh token is stored with the rotated session.
            g.pop("csrf_token", None)
            generate_csrf()
            return redirect(url_for("main.dashboard"))
        flash("Invalid username or password.", "error")
    return render_template("login.html")

@auth_bp.post("/logout")
@login_required
def logout():
    audit("auth.logout", g.user.username, g.user.id); db.session.commit(); session.clear()
    return redirect(url_for("auth.login"))
