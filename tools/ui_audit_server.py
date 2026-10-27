"""Disposable loopback UI audit server; uses an isolated random SQLite file."""
import os
import secrets
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinelsoc import create_app
from sentinelsoc.extensions import db
from sentinelsoc.models import DetectionRule, User

DB_NAME = f"ui-audit-{uuid.uuid4().hex}.db"
os.environ["SECRET_KEY"] = secrets.token_hex(32)
os.environ["DATABASE_URL"] = f"sqlite:///{DB_NAME}"
os.environ["COOKIE_SECURE"] = "false"

app = create_app({
    "TESTING": True,
    "SECRET_KEY": os.environ["SECRET_KEY"],
    "SQLALCHEMY_DATABASE_URI": os.environ["DATABASE_URL"],
    "SESSION_COOKIE_SECURE": False,
})

with app.app_context():
    db.create_all()
    admin = User(username="qa-auditor", role="admin")
    admin.set_password("Temporary-UI-Audit-2026!")
    db.session.add(admin)
    rules = [
        ("auth.bruteforce", "Repeated failures from one source", 5, 60),
        ("auth.account_failures", "Repeated failures against an account", 5, 60),
        ("auth.password_spray", "Password spraying indicator", 5, 60),
        ("auth.success_after_failures", "Success after repeated failures", 3, 300),
    ]
    for rule_id, name, threshold, window in rules:
        db.session.add(DetectionRule(id=rule_id, name=name, description=name,
                                     threshold=threshold, window_seconds=window))
    db.session.commit()
    db.session.remove()

print("Disposable isolated UI audit server on 127.0.0.1:5507", flush=True)
try:
    app.extensions["socketio"].run(
        app, host="127.0.0.1", port=5507, debug=False,
        use_reloader=False, allow_unsafe_werkzeug=True,
    )
finally:
    with app.app_context():
        db.session.remove()
        db.engine.dispose()
        database_file = Path(app.instance_path) / DB_NAME
        if database_file.exists():
            database_file.unlink()
