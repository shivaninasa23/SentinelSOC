import io
import json
from email.message import Message
from urllib.error import HTTPError, URLError
import pytest
from sentinelsoc.models import ThreatIntelCache
from sentinelsoc.threat_intel import enrich_ip

class Response:
    status=200
    def __enter__(self):return self
    def __exit__(self,*_):pass
    def read(self,_size):return json.dumps({"pulse_info":{"count":2,"pulses":[{"id":"p1","name":"Example pulse","private":True}]}}).encode()

def test_otx_positive_response_is_whitelisted_and_cached(app,monkeypatch):
    import sentinelsoc.threat_intel as ti
    app.config['OTX_API_KEY']='not-a-real-test-key'
    calls=[]
    monkeypatch.setattr(ti.urllib.request,'urlopen',lambda req,timeout:(calls.append((req,timeout)) or Response()))
    with app.app_context():
        first=enrich_ip('203.0.113.7')
        second=enrich_ip('203.0.113.7')
        assert first['status']=='positive' and first['provider']=='AlienVault OTX'
        assert second['cached'] and len(calls)==1
        assert 'private' not in first['result']['pulses'][0]
        assert ThreatIntelCache.query.count()==1

def test_otx_negative_and_unavailable_results_are_not_malicious_claims(app,monkeypatch):
    import sentinelsoc.threat_intel as ti
    app.config['OTX_API_KEY']='test-key'
    class Negative(Response):
        def read(self,_):return b'{"pulse_info":{"count":0,"pulses":[]}}'
    monkeypatch.setattr(ti.urllib.request,'urlopen',lambda *a,**k:Negative())
    with app.app_context():
        result=enrich_ip('203.0.113.8')
        assert result['status']=='negative' and 'not proof' in result['result']['note']
    app.config['OTX_API_KEY']=''
    with app.app_context():
        missing=enrich_ip('203.0.113.9')
        assert missing['status']=='unavailable' and missing['result']['reason']=='provider_not_configured'

def test_otx_rate_limit_honors_retry_after_and_bad_ip_rejected(app,monkeypatch):
    import sentinelsoc.threat_intel as ti
    app.config['OTX_API_KEY']='test-key'
    headers=Message();headers['Retry-After']='120'
    def limited(*_a,**_k):raise HTTPError('https://otx.example',429,'limited',headers,io.BytesIO())
    monkeypatch.setattr(ti.urllib.request,'urlopen',limited)
    with app.app_context():
        limited_result=enrich_ip('203.0.113.10')
        assert limited_result['status']=='unavailable' and limited_result['result']['retry_after']==120
        with pytest.raises(ValueError):enrich_ip('not an ip')

def test_otx_network_failure_returns_unavailable(app,monkeypatch):
    import sentinelsoc.threat_intel as ti
    app.config['OTX_API_KEY']='test-key'
    monkeypatch.setattr(ti.urllib.request,'urlopen',lambda *a,**k:(_ for _ in ()).throw(URLError('offline')))
    with app.app_context():assert enrich_ip('203.0.113.11')['status']=='unavailable'
