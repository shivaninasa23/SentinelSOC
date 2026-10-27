import json
from datetime import datetime, timezone, timedelta
from uuid import UUID
from sentinelsoc.extensions import db
from sentinelsoc.models import User, SecurityEvent, Alert, Incident, AuditRecord
from sentinelsoc.services import normalize_event, parse_auth_line

def csrf(client):
    import re
    body=client.get("/login").get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)',body).group(1)

def test_hash_login_and_auth_event(client,app):
    token=csrf(client)
    response=client.post('/login',data={'username':'analyst','password':'Correct-Horse-Battery-4!','csrf_token':token})
    assert response.status_code==302
    with app.app_context():
        u=User.query.filter_by(username='analyst').first(); assert u.password_hash!='Correct-Horse-Battery-4!';assert u.check_password('Correct-Horse-Battery-4!')
        assert SecurityEvent.query.filter_by(event_type='authentication',outcome='success').count()==1

def test_real_login_failures_trigger_alert(client,app):
    token=csrf(client)
    for _ in range(5):
        response=client.post('/login',data={'username':'analyst','password':'wrong-password','csrf_token':token})
        assert response.status_code==200
    with app.app_context():
        assert SecurityEvent.query.filter_by(source_system='sentinelsoc-auth',outcome='failure').count()==5
        alert=Alert.query.filter_by(rule_id='auth.bruteforce').one()
        assert alert.severity=='high' and len(alert.event_ids)==5

def test_csrf_and_generic_login_error(client):
    assert client.post('/login',data={'username':'nope','password':'bad'}).status_code==400
    r=client.post('/login',data={'username':'unknown','password':'bad','csrf_token':csrf(client)})
    assert b'Invalid username or password' in r.data

def test_analyst_cannot_open_user_management(client):
    token=csrf(client)
    client.post('/login',data={'username':'analyst','password':'Correct-Horse-Battery-4!','csrf_token':token})
    assert client.get('/users').status_code==403

def test_admin_cli_provisioning(app,monkeypatch):
    monkeypatch.setattr('sentinelsoc.cli.getpass.getpass',lambda _prompt:'Admin-Password-Long-42!')
    with app.app_context():
        User.query.filter_by(username='admin').delete();db.session.commit()
    result=app.test_cli_runner().invoke(args=['create-admin'],input='firstadmin\n')
    assert result.exit_code==0, result.output
    with app.app_context():
        user=User.query.filter_by(username='firstadmin').one()
        assert user.role=='admin' and user.check_password('Admin-Password-Long-42!')

def test_access_control_and_ingestion_token(client):
    assert client.get('/api/events').status_code in (302,401)
    r=client.post('/api/ingest',json={"event_type":"authentication"});assert r.status_code==401

def test_normalization_and_parser():
    e=normalize_event({'event_type':'authentication','source_system':'test','description':'login','source_ip':'127.0.0.1','outcome':'failure'})
    assert e['occurred_at'].tzinfo==timezone.utc
    try:normalize_event({'event_type':'authentication','source_system':'test','description':'x','source_ip':'999.1.1.1'})
    except ValueError:pass
    else:assert False
    parsed=parse_auth_line('2025-01-01T00:00:00Z,authentication,127.0.0.1,alice,failure,login denied')
    assert parsed['username']=='alice'

def test_bruteforce_threshold_and_duplicate_prevention(app,client):
    from sentinelsoc.services import ingest_event
    with app.app_context():
        now=datetime.now(timezone.utc)
        for i in range(4): ingest_event({'event_id':str(UUID(int=i+1)),'event_type':'authentication','source_system':'test','description':'failed','source_ip':'198.51.100.8','username':'alice','outcome':'failure','occurred_at':(now-timedelta(seconds=10-i)).isoformat()})
        assert Alert.query.count()==0
        ingest_event({'event_id':str(UUID(int=5)),'event_type':'authentication','source_system':'test','description':'failed','source_ip':'198.51.100.8','username':'alice','outcome':'failure','occurred_at':now.isoformat()})
        assert Alert.query.filter_by(rule_id='auth.bruteforce').count()==1
        ingest_event({'event_id':str(UUID(int=6)),'event_type':'authentication','source_system':'test','description':'failed','source_ip':'198.51.100.8','username':'alice','outcome':'failure','occurred_at':(now+timedelta(seconds=1)).isoformat()})
        assert Alert.query.filter_by(rule_id='auth.bruteforce').count()==1

def test_bad_ingestion_and_unauthenticated_api_token(client,app):
    assert client.post('/api/ingest',headers={'X-Ingest-Token':'test-ingest-token'},json={'source_ip':'999.1.2.3'}).status_code==400
    assert client.post('/api/ingest',headers={'X-Ingest-Token':'test-ingest-token'},json={'event_type':'authentication','source_system':'test','description':'x','source_ip':'203.0.113.2','outcome':'failure'}).status_code==201

def test_dashboard_websocket_requires_login(app):
    sio=app.extensions['socketio'].test_client(app,namespace='/live') if 'socketio' in app.extensions else None
    # Flask-SocketIO stores itself on app.extensions on supported versions.
    assert sio is not None and not sio.is_connected('/live')

def test_demo_label_and_alert_to_incident(app,client):
    token=csrf(client);client.post('/login',data={'username':'analyst','password':'Correct-Horse-Battery-4!','csrf_token':token})
    import re
    token=re.search(r'name="csrf-token" content="([^"]+)',client.get('/').get_data(as_text=True)).group(1)
    resp=client.post('/api/demo',json={'scenario':'bruteforce'},headers={'X-CSRFToken':token})
    assert resp.status_code==200 and resp.json['simulated'], resp.get_data(as_text=True)
    with app.app_context():
        assert SecurityEvent.query.filter_by(simulated=True).count()==5
        a=Alert.query.first();assert a and a.simulated
        assert all(SecurityEvent.query.filter_by(event_id=x).first().simulated for x in a.event_ids)
    alert_id=Alert.query.first().alert_id
    converted=client.post(f'/api/alert/{alert_id}/incident',json={},headers={'X-CSRFToken':token})
    assert converted.status_code==201
    incident_id=converted.json['incident_id']
    updated=client.post(f'/api/incident/{incident_id}/update',json={'status':'resolved','note':'Reviewed','resolution_notes':'Reviewed and closed as a demo'},headers={'X-CSRFToken':token})
    assert updated.status_code==200
    with app.app_context():assert Incident.query.filter_by(incident_id=incident_id).first().status=='resolved';assert AuditRecord.query.filter_by(action='incident.updated').count()==1

def test_csv_formula_protection(app,client):
    token=csrf(client);client.post('/login',data={'username':'analyst','password':'Correct-Horse-Battery-4!','csrf_token':token})
    with app.app_context():
        from sentinelsoc.services import ingest_event
        ingest_event({'event_type':'test','source_system':'test','description':'=1+1','source_ip':'127.0.0.1'})
    response=client.get('/api/export/events.csv')
    assert response.status_code==200 and "'=1+1" in response.get_data(as_text=True)
