from io import BytesIO
import re
from sentinelsoc.models import SecurityEvent, EventImport

CSV=b"2026-10-27T12:00:00Z,authentication,198.51.100.9,alice,failure,Failed sign in\nnot-a-date,authentication,not-ip,bob,failure,Malformed\n"

def _csrf(client):return re.search(r'name="csrf_token" value="([^"]+)',client.get('/login').get_data(as_text=True)).group(1)
def _login(client):
    token=_csrf(client);client.post('/login',data={'username':'analyst','password':'Correct-Horse-Battery-4!','csrf_token':token})
    return re.search(r'name="csrf-token" content="([^"]+)',client.get('/').get_data(as_text=True)).group(1)
def _upload(client,url,token,filename='auth.csv',content=CSV):
    return client.post(url,data={'file':(BytesIO(content),filename)},headers={'X-CSRFToken':token},content_type='multipart/form-data')

def test_preview_import_dedup_provenance_and_malformed_summary(app,client):
    token=_login(client)
    preview=_upload(client,'/api/imports/preview',token,'../../auth.csv')
    assert preview.status_code==200 and preview.json['would_import']==1 and preview.json['malformed']==1
    assert preview.json['filename']=='auth.csv'
    assert SecurityEvent.query.filter_by(source_system='csv-import').count()==0
    imported=_upload(client,'/api/imports',token)
    assert imported.status_code==201 and imported.json['imported']==1 and imported.json['malformed']==1
    duplicate=_upload(client,'/api/imports',token)
    assert duplicate.status_code==201 and duplicate.json['imported']==0 and duplicate.json['duplicates']==1
    with app.app_context():
        event=SecurityEvent.query.filter_by(source_system='csv-import').one()
        assert not event.simulated and event.import_record_id
        record=EventImport.query.filter_by(id=event.import_record_id).one()
        assert record.filename=='auth.csv' and record.imported_count==1 and record.malformed_count==1

def test_upload_rejects_wrong_extension_encoding_and_size(client):
    token=_login(client)
    assert _upload(client,'/api/imports/preview',token,'logs.exe').status_code==400
    assert _upload(client,'/api/imports/preview',token,'logs.csv',b'\xff\xfe').status_code==400
    assert _upload(client,'/api/imports/preview',token,'logs.csv',b'x'*1_048_600).status_code==413
