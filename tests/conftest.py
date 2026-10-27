import pytest
from sentinelsoc import create_app
from sentinelsoc.extensions import db
from sentinelsoc.models import User, DetectionRule

@pytest.fixture
def app(monkeypatch):
    monkeypatch.setenv("INGEST_TOKEN","test-ingest-token")
    app=create_app({"TESTING":True,"SECRET_KEY":"test-only-secret-key","SQLALCHEMY_DATABASE_URI":"sqlite://","WTF_CSRF_ENABLED":True,"RATELIMIT_ENABLED":False,"BRUTE_FORCE_THRESHOLD":5,"BRUTE_FORCE_WINDOW_SECONDS":60})
    with app.app_context():
        db.create_all()
        for rid,name,threshold,window in [("auth.bruteforce","Repeated failures from one source",5,60),("auth.account_failures","Account failures",5,60),("auth.password_spray","Password spray",5,60),("auth.success_after_failures","Success after failures",3,300)]:
            db.session.add(DetectionRule(id=rid,name=name,description="threshold failures",threshold=threshold,window_seconds=window))
        u=User(username="analyst",role="analyst");u.set_password("Correct-Horse-Battery-4!");db.session.add(u)
        a=User(username="admin",role="admin");a.set_password("Correct-Horse-Battery-5!");db.session.add(a);db.session.commit()
        yield app
        db.session.remove();db.drop_all()

@pytest.fixture
def client(app): return app.test_client()
