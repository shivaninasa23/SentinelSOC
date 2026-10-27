import re
from sentinelsoc.models import User, Alert, Incident, IncidentAlert, InvestigationNote, AuditRecord, SecurityEvent
from sentinelsoc.extensions import db
from sentinelsoc.services import ingest_event
from datetime import datetime, timezone, timedelta
from uuid import UUID

def csrf(client):return re.search(r'name="csrf_token" value="([^"]+)',client.get('/login').get_data(as_text=True)).group(1)
def login(client,user='analyst',password='Correct-Horse-Battery-4!'):
    token=csrf(client);response=client.post('/login',data={'username':user,'password':password,'csrf_token':token})
    home=client.get('/')
    match=re.search(r'name="csrf-token" content="([^"]+)',home.get_data(as_text=True))
    assert match, f"login={response.status_code} {response.get_data(as_text=True)}, home={home.status_code}, body={home.get_data(as_text=True)[:300]}"
    return match.group(1)

def _alert(app):
    with app.app_context():
        now=datetime.now(timezone.utc)
        for i in range(5):
            ingest_event({'event_id':str(UUID(int=500+i)),'event_type':'authentication','source_system':'test','description':'failure','source_ip':'198.51.100.77','username':'target','outcome':'failure','occurred_at':(now-timedelta(seconds=4-i)).isoformat()})
        return Alert.query.filter_by(rule_id='auth.bruteforce').first().alert_id

def test_alert_assignment_and_role_restrictions(app,client):
    alert_id=_alert(app);token=login(client,'admin','Correct-Horse-Battery-5!')
    with app.app_context():analyst=User.query.filter_by(username='analyst').first()
    response=client.post(f'/api/alert/{alert_id}/assign',json={'assigned_to':analyst.id},headers={'X-CSRFToken':token})
    assert response.status_code==200
    with app.app_context():
        alert=Alert.query.filter_by(alert_id=alert_id).one();assert alert.assigned_to==analyst.id
        assert AuditRecord.query.filter_by(action='alert.assigned').count()==1
    analyst_client=app.test_client()
    with analyst_client.session_transaction() as sess:sess['user_id']=analyst.id
    app.config['WTF_CSRF_ENABLED']=False
    assert analyst_client.post(f'/api/rule/auth.bruteforce',json={'enabled':False}).status_code==403

def test_incident_assignment_notes_lifecycle_related_alert_and_report(app,client):
    alert_id=_alert(app);token=login(client)
    incident=client.post('/api/incidents',json={'title':'Investigation A','severity':'high'},headers={'X-CSRFToken':token})
    assert incident.status_code==201
    incident_id=incident.json['incident_id']
    aid=client.post(f'/api/incident/{incident_id}/alerts',json={'alert_id':alert_id},headers={'X-CSRFToken':token})
    assert aid.status_code==201
    with app.app_context():analyst_id=User.query.filter_by(username='analyst').first().id
    assert client.post(f'/api/incident/{incident_id}/assign',json={'assigned_to':analyst_id},headers={'X-CSRFToken':token}).status_code==200
    update=client.post(f'/api/incident/{incident_id}/update',json={'status':'investigating','note':'Reviewed the evidence.'},headers={'X-CSRFToken':token})
    assert update.status_code==200
    detail=client.get(f'/api/incident/{incident_id}').json['incident']
    assert detail['timeline'][0]['kind']=='event' and any(x['kind']=='note' for x in detail['timeline'])
    assert client.post(f'/api/incident/{incident_id}/update',json={'status':'resolved'},headers={'X-CSRFToken':token}).status_code==400
    resolved=client.post(f'/api/incident/{incident_id}/update',json={'status':'resolved','resolution_notes':'Credentials reset and MFA verified.'},headers={'X-CSRFToken':token})
    assert resolved.status_code==200
    with app.app_context():
        evidence_id=Alert.query.filter_by(alert_id=alert_id).one().event_ids[0]
        db.session.query(SecurityEvent).filter_by(event_id=evidence_id).update({"description":"<script>safe-test</script>"});db.session.commit()
    report=client.get(f'/api/export/incident/{incident_id}.html')
    assert report.status_code==200 and b'&lt;script&gt;safe-test&lt;/script&gt;' in report.data
    with app.app_context():assert IncidentAlert.query.count()==1 and Incident.query.filter_by(incident_id=incident_id).one().resolved_at

def test_simulated_alert_cannot_link_to_observed_incident(app,client):
    token=login(client)
    simulated=client.post('/api/demo',json={'scenario':'bruteforce'},headers={'X-CSRFToken':token})
    assert simulated.status_code==200
    with app.app_context():alert=Alert.query.filter_by(simulated=True).first()
    manual=client.post('/api/incidents',json={'title':'Observed case'},headers={'X-CSRFToken':token}).json['incident_id']
    response=client.post(f'/api/incident/{manual}/alerts',json={'alert_id':alert.alert_id},headers={'X-CSRFToken':token})
    assert response.status_code==400

def test_admin_user_creation_update_and_self_protection(app,client):
    token=login(client,'admin','Correct-Horse-Battery-5!')
    created=client.post('/api/users',json={'username':'new.analyst','password':'Long-First-Password-99!','role':'analyst'},headers={'X-CSRFToken':token})
    assert created.status_code==201
    user_id=created.json['user']['id']
    rejected=client.put(f'/api/users/{user_id}',json={'role':'admin','active':'false'},headers={'X-CSRFToken':token})
    assert rejected.status_code==400
    with app.app_context():assert db.session.get(User,user_id).role=='analyst' and db.session.get(User,user_id).active
    assert client.put(f'/api/users/{user_id}',json={'active':False},headers={'X-CSRFToken':token}).status_code==200
    with app.app_context():assert not db.session.get(User,user_id).active
    with app.app_context():admin_id=User.query.filter_by(username='admin').one().id
    assert client.put(f'/api/users/{admin_id}',json={'active':False},headers={'X-CSRFToken':token}).status_code==400
    analyst=app.test_client()
    with app.app_context():analyst_id=User.query.filter_by(username='analyst').one().id
    with analyst.session_transaction() as sess:sess['user_id']=analyst_id
    app.config['WTF_CSRF_ENABLED']=False
    assert analyst.post('/api/users',json={'username':'bad.user','password':'Long-First-Password-99!'}).status_code==403

def test_rule_configuration_validation_and_audit(app,client):
    token=login(client,'admin','Correct-Horse-Battery-5!')
    invalid=client.post('/api/rule/auth.bruteforce',json={'threshold':12,'enabled':'false'},headers={'X-CSRFToken':token})
    assert invalid.status_code==400
    with app.app_context():
        from sentinelsoc.models import DetectionRule
        rule=db.session.get(DetectionRule,'auth.bruteforce')
        assert rule.threshold==5 and rule.enabled
    changed=client.post('/api/rule/auth.bruteforce',json={'threshold':7,'window_seconds':120,'enabled':False},headers={'X-CSRFToken':token})
    assert changed.status_code==200 and changed.json['threshold']==7 and changed.json['enabled'] is False
    with app.app_context():assert AuditRecord.query.filter_by(action='rule.updated').count()==1

def test_analytics_and_filtered_csv_use_database_records(app,client):
    token=login(client)
    with app.app_context():
        ingest_event({'event_id':str(UUID(int=901)),'event_type':'authentication','source_system':'test','description':'filtered failure','source_ip':'192.0.2.77','username':'alice','outcome':'failure'})
        ingest_event({'event_id':str(UUID(int=902)),'event_type':'authentication','source_system':'test','description':'<script>alert(1)</script>','source_ip':'192.0.2.78','username':'bob','outcome':'success'},simulated=True)
    dashboard=client.get('/api/dashboard').json
    assert dashboard['sources'][0]['source_ip']=='192.0.2.77' and len(dashboard['rules'])==4
    analytics=client.get('/api/analytics?days=7').json
    assert analytics['simulated'] is False and sum(x['count'] for x in analytics['event_volume'])>=2
    simulated=client.get('/api/analytics?days=7&simulated=true').json
    assert simulated['simulated'] is True and simulated['authentication_outcomes']['success']==1
    exported=client.get('/api/export/events.csv?source_ip=192.0.2.77&outcome=failure&simulated=false').get_data(as_text=True)
    assert 'filtered failure' in exported and '192.0.2.78' not in exported
    assert client.get('/api/export/alerts.csv?severity=high').status_code==200
