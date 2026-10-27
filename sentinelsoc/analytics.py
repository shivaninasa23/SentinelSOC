from collections import Counter
from datetime import date, datetime, time, timedelta, timezone
from .models import SecurityEvent, Alert, Incident

def analytics(days=7, start=None, end=None, simulated=False):
    today=datetime.now(timezone.utc).date()
    if start:
        try:start=date.fromisoformat(start)
        except ValueError:raise ValueError("start must use YYYY-MM-DD")
    if end:
        try:end=date.fromisoformat(end)
        except ValueError:raise ValueError("end must use YYYY-MM-DD")
    end=end or today
    start=start or end-timedelta(days=max(1,min(days,90))-1)
    if start>end or (end-start).days>90:raise ValueError("date range must be ordered and no longer than 91 days")
    lower=datetime.combine(start,time.min,tzinfo=timezone.utc);upper=datetime.combine(end+timedelta(days=1),time.min,tzinfo=timezone.utc)
    events=SecurityEvent.query.filter(SecurityEvent.occurred_at>=lower,SecurityEvent.occurred_at<upper,SecurityEvent.simulated==simulated).all()
    alerts=Alert.query.filter(Alert.created_at>=lower,Alert.created_at<upper,Alert.simulated==simulated).all()
    day_keys=[(start+timedelta(days=i)).isoformat() for i in range((end-start).days+1)]
    event_volume=Counter(e.occurred_at.date().isoformat() for e in events)
    alert_volume=Counter(a.created_at.date().isoformat() for a in alerts)
    severity=Counter(a.severity for a in alerts)
    outcomes=Counter(e.outcome or "unknown" for e in events if e.event_type=="authentication")
    sources=Counter(e.source_ip for e in events if e.source_ip)
    rules=Counter(a.rule_id for a in alerts)
    incidents=Incident.query.filter(Incident.created_at>=lower,Incident.created_at<upper,Incident.simulated==simulated).all()
    resolution_hours=[(i.resolved_at-i.created_at).total_seconds()/3600 for i in incidents if i.resolved_at]
    return {"range":{"start":start.isoformat(),"end":end.isoformat()},"simulated":simulated,
        "event_volume":[{"date":d,"count":event_volume[d]} for d in day_keys],
        "alert_trend":[{"date":d,"count":alert_volume[d]} for d in day_keys],
        "severity_distribution":dict(severity),"authentication_outcomes":dict(outcomes),
        "top_sources":[{"source_ip":ip,"count":count} for ip,count in sources.most_common(10)],
        "rule_triggers":dict(rules),"incident_resolution":{"created":len(incidents),"resolved":sum(bool(i.resolved_at) for i in incidents),
            "open":sum(i.status in {"open","investigating"} for i in incidents),"mean_hours":round(sum(resolution_hours)/len(resolution_hours),2) if resolution_hours else None}}
