from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from threading import Barrier
from uuid import UUID

from sentinelsoc import create_app
from sentinelsoc.extensions import db
from sentinelsoc.models import Alert, DetectionRule
from sentinelsoc.services import ingest_event


def test_concurrent_same_source_events_create_at_most_one_bruteforce_alert(tmp_path):
    database = tmp_path / "concurrent-detection.sqlite"
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "isolated-concurrency-test-key",
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database.as_posix()}",
        "SQLALCHEMY_ENGINE_OPTIONS": {"connect_args": {"timeout": 15}},
    })
    with app.app_context():
        db.create_all()
        db.session.add(DetectionRule(
            id="auth.bruteforce", name="Repeated failures", description="Test rule",
            threshold=5, window_seconds=60,
        ))
        db.session.commit()

    barrier = Barrier(5)
    occurred = datetime.now(timezone.utc).isoformat()

    def send(number):
        payload = {
            "event_id": str(UUID(int=3000 + number)),
            "event_type": "authentication",
            "source_system": "concurrency-test",
            "description": "controlled concurrent failure",
            "source_ip": "192.0.2.230",
            "username": "concurrent-test-user",
            "outcome": "failure",
            "occurred_at": occurred,
        }
        with app.app_context():
            barrier.wait(timeout=10)
            return ingest_event(payload)[1]

    try:
        with ThreadPoolExecutor(max_workers=5) as pool:
            created = list(pool.map(send, range(5)))
        assert all(created)
        with app.app_context():
            assert Alert.query.filter_by(rule_id="auth.bruteforce").count() <= 1
            assert Alert.query.filter_by(rule_id="auth.bruteforce").one().evidence["observed"] == 5
    finally:
        with app.app_context():
            db.session.remove()
            db.drop_all()
            db.engine.dispose()
