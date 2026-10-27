import os
import logging
import json
from datetime import timedelta
from flask import Flask, jsonify
from dotenv import load_dotenv
from flask_socketio import SocketIO
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from .extensions import db, migrate

class JsonFormatter(logging.Formatter):
    def format(self, record):
        return json.dumps({"timestamp":self.formatTime(record),"level":record.levelname,"logger":record.name,"message":record.getMessage()})

csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, default_limits=[])

def create_app(test_config=None):
    load_dotenv()
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.getenv("SECRET_KEY", ""),
        SQLALCHEMY_DATABASE_URI=os.getenv("DATABASE_URL", "sqlite:///sentinelsoc.db"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        MAX_CONTENT_LENGTH=1024 * 1024,
        RATELIMIT_STORAGE_URI=os.getenv("RATELIMIT_STORAGE_URI", "memory://"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "false").lower() == "true",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        BRUTE_FORCE_THRESHOLD=int(os.getenv("BRUTE_FORCE_THRESHOLD", "5")),
        BRUTE_FORCE_WINDOW_SECONDS=int(os.getenv("BRUTE_FORCE_WINDOW_SECONDS", "60")),
        OTX_API_KEY=os.getenv("OTX_API_KEY", ""),
        INGEST_TOKEN=os.getenv("INGEST_TOKEN", ""),
        THREAT_INTEL_CACHE_SECONDS=int(os.getenv("THREAT_INTEL_CACHE_SECONDS", "21600")),
        EVENT_RETENTION_DAYS=int(os.getenv("EVENT_RETENTION_DAYS", "90")),
    )
    if test_config:
        app.config.update(test_config)
    if not app.config["SECRET_KEY"] and not app.config.get("TESTING"):
        raise RuntimeError("Set SECRET_KEY in the environment before starting SentinelSOC.")
    if not app.config.get("TESTING") and len(app.config["SECRET_KEY"])<32:
        raise RuntimeError("SECRET_KEY must contain at least 32 characters.")
    if not 2<=app.config["BRUTE_FORCE_THRESHOLD"]<=100 or not 10<=app.config["BRUTE_FORCE_WINDOW_SECONDS"]<=3600:
        raise RuntimeError("Brute-force threshold must be 2–100 and window must be 10–3600 seconds.")
    if not 60<=app.config["THREAT_INTEL_CACHE_SECONDS"]<=604800 or not 1<=app.config["EVENT_RETENTION_DAYS"]<=3650:
        raise RuntimeError("Threat cache TTL must be 60–604800 seconds and retention must be 1–3650 days.")
    os.makedirs(app.instance_path, exist_ok=True)
    handler=logging.StreamHandler();handler.setFormatter(JsonFormatter())
    app.logger.handlers=[handler];app.logger.setLevel(logging.INFO)
    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    limiter.init_app(app)
    from . import models  # noqa: F401
    from .auth import auth_bp
    from .routes import main_bp
    from .api import api_bp
    from .api import socket_connect
    socketio = SocketIO(async_mode="threading")
    socketio.on_event("connect", socket_connect, namespace="/live")
    socketio.init_app(app)
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp, url_prefix="/api")
    from .cli import register_commands
    register_commands(app)
    @app.errorhandler(413)
    def too_large(_): return jsonify(error="Request exceeds the 1 MB limit."), 413
    @app.errorhandler(404)
    def not_found(_): return jsonify(error="Not found"), 404
    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error("Unhandled application error", exc_info=error)
        db.session.rollback()
        return jsonify(error="An internal error occurred."), 500
    return app
