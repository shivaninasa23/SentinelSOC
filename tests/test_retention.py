from datetime import datetime, timezone, timedelta
from uuid import UUID
from sentinelsoc.extensions import db
from sentinelsoc.models import SecurityEvent, Alert, AuditRecord

def _event(event_id,description):
    return SecurityEvent(event_id=str(UUID(int=event_id)),occurred_at=datetime.now(timezone.utc)-timedelta(days=10),
        source_system='retention-test',event_type='system',description=description,severity='low',metadata_json={},simulated=False)

def test_retention_dry_run_and_applied_run_preserve_alert_evidence(app):
    with app.app_context():
        disposable=_event(1101,'old unrelated');evidence=_event(1102,'old evidence');db.session.add_all([disposable,evidence]);db.session.flush()
        db.session.add(Alert(alert_id=str(UUID(int=1199)),rule_id='test.rule',rule_name='Test',severity='high',description='evidence required',evidence={},event_ids=[evidence.event_id],source_ip=None,username=None,window_seconds=60,explanation='test',recommendation='test',episode_key='test:episode'))
        db.session.commit()
    runner=app.test_cli_runner()
    dry=runner.invoke(args=['retain-events','--days','1'])
    assert dry.exit_code==0 and 'eligible for deletion: 1' in dry.output
    with app.app_context():assert SecurityEvent.query.count()==2
    applied=runner.invoke(args=['retain-events','--days','1','--apply'])
    assert applied.exit_code==0 and 'Deleted 1' in applied.output
    with app.app_context():
        assert SecurityEvent.query.filter_by(description='old unrelated').count()==0
        assert SecurityEvent.query.filter_by(description='old evidence').count()==1
        assert AuditRecord.query.filter_by(action='events.retention_applied').count()==1
