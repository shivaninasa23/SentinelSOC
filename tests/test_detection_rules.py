from datetime import datetime, timezone, timedelta
from uuid import UUID
from sentinelsoc.extensions import db
from sentinelsoc.models import Alert, SecurityEvent
from sentinelsoc.services import ingest_event

def event(i, when, user, ip, outcome="failure", simulated=False):
    return ingest_event({"event_id":str(UUID(int=i)),"event_type":"authentication","source_system":"test",
        "description":f"auth {outcome}","occurred_at":when.isoformat(),"source_ip":ip,"username":user,"outcome":outcome},simulated=simulated)

def test_account_failures_across_sources_trigger_account_rule(app):
    with app.app_context():
        now=datetime.now(timezone.utc)
        for i in range(1,6): event(i,now-timedelta(seconds=5-i),"target","198.51.100."+str(i))
        alert=Alert.query.filter_by(rule_id="auth.account_failures").one()
        assert alert.username=="target" and len(alert.evidence["event_ids"])==5

def test_password_spray_detects_distinct_accounts_from_one_ip(app):
    with app.app_context():
        now=datetime.now(timezone.utc)
        for i in range(11,16): event(i,now-timedelta(seconds=16-i),f"user-{i}","203.0.113.9")
        alert=Alert.query.filter_by(rule_id="auth.password_spray").one()
        assert alert.source_ip=="203.0.113.9" and alert.evidence["observed"]==5
        assert alert.evidence["mitre_attack"]["id"]=="T1110.003"

def test_success_after_repeated_failures_has_both_outcomes_as_evidence(app):
    with app.app_context():
        now=datetime.now(timezone.utc)
        for i,offset in zip(range(21,24),(4,3,2)): event(i,now-timedelta(seconds=offset),"alice",f"198.51.100.{i}")
        event(24,now,"alice","192.0.2.24","success")
        alert=Alert.query.filter_by(rule_id="auth.success_after_failures").one()
        assert len(alert.event_ids)==4
        assert SecurityEvent.query.filter(SecurityEvent.event_id.in_(alert.event_ids),SecurityEvent.outcome=="success").count()==1

def test_detection_windows_are_utc_bounded_and_simulation_separated(app):
    with app.app_context():
        now=datetime.now(timezone.utc)
        for i in range(31,35): event(i,now-timedelta(seconds=100+i),"old","192.0.2.1")
        assert Alert.query.filter_by(rule_id="auth.account_failures").count()==0
        for i in range(41,46): event(i,now-timedelta(seconds=5),f"lab-{i}","192.0.2.2",simulated=True)
        assert Alert.query.filter_by(rule_id="auth.password_spray",simulated=True).count()==1
        assert Alert.query.filter_by(rule_id="auth.password_spray",simulated=False).count()==0

def test_out_of_order_failures_still_correlate(app):
    with app.app_context():
        now=datetime.now(timezone.utc)
        for i,offset in zip(range(51,56),(0,1,2,3,4)):
            event(i,now-timedelta(seconds=offset),f"late-{i}","192.0.2.51")
        alert=Alert.query.filter_by(rule_id="auth.password_spray").one()
        assert len(alert.event_ids)==5

def test_success_arriving_before_its_failures_is_correlated(app):
    with app.app_context():
        now=datetime.now(timezone.utc)
        event(61,now,"prior-failures","192.0.2.61","success")
        for i,offset in zip(range(62,65),(3,2,1)):
            event(i,now-timedelta(seconds=offset),"prior-failures",f"192.0.2.{i}")
        alert=Alert.query.filter_by(rule_id="auth.success_after_failures").one()
        assert alert.event_ids[0] != alert.event_ids[-1]
        assert SecurityEvent.query.filter(SecurityEvent.event_id.in_(alert.event_ids),SecurityEvent.outcome=="success").count()==1

def test_bruteforce_rolling_window_includes_60s_boundary_not_61s(app):
    with app.app_context():
        now=datetime.now(timezone.utc)
        for i,offset in zip(range(71,76),(61,45,30,15,0)):
            event(i,now-timedelta(seconds=offset),f"boundary-{i}","192.0.2.71")
        assert Alert.query.filter_by(rule_id="auth.bruteforce").count()==0
        for i,offset in zip(range(81,86),(60,45,30,15,0)):
            event(i,now+timedelta(seconds=1)-timedelta(seconds=offset),f"exact-{i}","192.0.2.81")
        assert Alert.query.filter_by(rule_id="auth.bruteforce").count()==1
