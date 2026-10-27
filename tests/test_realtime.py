import re
from uuid import UUID
from sentinelsoc.extensions import db
from sentinelsoc.models import SecurityEvent
from sentinelsoc.services import ingest_event

def _login(client):
    page=client.get('/login').get_data(as_text=True);token=re.search(r'name="csrf_token" value="([^"]+)',page).group(1)
    response=client.post('/login',data={'username':'analyst','password':'Correct-Horse-Battery-4!','csrf_token':token})
    assert response.status_code==302, response.get_data(as_text=True)

def _event(n,description):
    return ingest_event({'event_id':str(UUID(int=n)),'event_type':'system','source_system':'socket-test','description':description})[0]

def test_socket_auth_delivery_reconnect_and_snapshot_recovery(app,client):
    sio=app.extensions['socketio'].test_client(app,namespace='/live')
    assert not sio.is_connected('/live')
    cross=app.extensions['socketio'].test_client(app,namespace='/live',headers={'Origin':'https://attacker.invalid'})
    assert not cross.is_connected('/live')
    _login(client)
    with client.session_transaction() as sess:assert sess.get('user_id') is not None
    sio=app.extensions['socketio'].test_client(app,namespace='/live',flask_test_client=client)
    assert sio.is_connected('/live')
    with app.app_context():event=_event(1001,'live update')
    received=sio.get_received('/live')
    assert any(item['name']=='event' and item['args'][0]['event_id']==event.event_id for item in received)
    first=event
    sio.get_received('/live');sio.disconnect(namespace='/live')
    with app.app_context():missed=_event(1002,'missed while disconnected')
    reconnected=app.extensions['socketio'].test_client(app,namespace='/live',flask_test_client=client)
    assert reconnected.is_connected('/live')
    recovered=client.get(f'/api/events?after_id={first.id}&order=asc')
    assert recovered.status_code==200 and any(e['event_id']==missed.event_id for e in recovered.json['events'])
    with app.app_context():
        from sentinelsoc.models import User
        analyst=User.query.filter_by(username='analyst').one();analyst.active=False;db.session.commit()
        _event(1003,'after account deactivation')
    assert not reconnected.get_received('/live')
    assert SecurityEvent.query.count()==4 # login event plus three test events
    reconnected.disconnect(namespace='/live')
