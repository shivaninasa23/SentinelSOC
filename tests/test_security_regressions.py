import re

from sentinelsoc.extensions import db
from sentinelsoc.models import SecurityEvent
from sentinelsoc.services import ingest_event


def csrf_token(client):
    html = client.get("/login").get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)', html).group(1)


def test_sql_injection_payloads_do_not_authenticate_or_change_query_results(app, client):
    token = csrf_token(client)
    response = client.post("/login", data={
        "username": "' OR 1=1 --",
        "password": "anything",
        "csrf_token": token,
    })
    assert response.status_code == 200
    assert b"Invalid username or password" in response.data
    with client.session_transaction() as session:
        assert "user_id" not in session

    with app.app_context():
        ingest_event({
            "event_type": "system", "source_system": "test",
            "description": "only expected event", "username": "normal-user",
        })
    token = csrf_token(client)
    login = client.post("/login", data={
        "username": "analyst", "password": "Correct-Horse-Battery-4!",
        "csrf_token": token,
    })
    assert login.status_code == 302
    injection = client.get("/api/events", query_string={"q": "x' OR 1=1 --"})
    assert injection.status_code == 200
    assert injection.json["total"] == 0
    assert injection.json["events"] == []
    with app.app_context():
        assert SecurityEvent.query.count() == 3  # failed login, test event and successful login


def test_login_rotates_pre_authentication_session_state(app, client):
    with client.session_transaction() as session:
        session["csrf_nonce"] = "pre-authentication-marker"
        session["user_id"] = -999
    token = csrf_token(client)
    response = client.post("/login", data={
        "username": "analyst", "password": "Correct-Horse-Battery-4!",
        "csrf_token": token,
    })
    assert response.status_code == 302
    with client.session_transaction() as session:
        assert session["user_id"] != -999
        assert session["csrf_nonce"] != "pre-authentication-marker"
        authenticated_nonce = session["csrf_nonce"]
    client.post("/logout", data={"csrf_token": csrf_token(client)})
    with client.session_transaction() as session:
        assert "user_id" not in session
        assert "csrf_nonce" not in session
    assert authenticated_nonce


def test_login_rate_limit_rejects_ninth_post_from_one_source():
    from sentinelsoc import create_app
    app = create_app({
        "TESTING": True, "SECRET_KEY": "test-rate-limit-secret",
        "SQLALCHEMY_DATABASE_URI": "sqlite://", "WTF_CSRF_ENABLED": True,
        "RATELIMIT_ENABLED": True, "RATELIMIT_STORAGE_URI": "memory://",
    })
    with app.app_context():
        db.create_all()
    client = app.test_client()
    token = csrf_token(client)
    statuses = []
    for _ in range(9):
        response = client.post("/login", data={
            "username": "missing-user", "password": "incorrect",
            "csrf_token": token,
        })
        statuses.append(response.status_code)
    assert statuses[:8] == [200] * 8
    assert statuses[8] == 429
    with app.app_context():
        db.session.remove()
        db.drop_all()
        db.engine.dispose()

