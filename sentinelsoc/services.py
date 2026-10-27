import ipaddress
import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy.exc import IntegrityError
from .extensions import db
from .models import SecurityEvent, Alert, AuditRecord, DetectionRule

SEVERITIES = {"critical", "high", "medium", "low"}

def normalize_event(payload, simulated=False):
    if not isinstance(payload, dict): raise ValueError("Event must be a JSON object")
    event_type = str(payload.get("event_type", "")).strip()[:64]
    source = str(payload.get("source_system", "")).strip()[:128]
    description = str(payload.get("description", "")).strip()[:500]
    if not event_type or not source or not description: raise ValueError("event_type, source_system and description are required")
    outcome = payload.get("outcome")
    if outcome not in (None, "success", "failure"): raise ValueError("outcome must be success or failure")
    severity = payload.get("severity", "low")
    if severity not in SEVERITIES: raise ValueError("invalid severity")
    source_ip = payload.get("source_ip")
    if source_ip:
        try: source_ip = str(ipaddress.ip_address(source_ip))
        except ValueError: raise ValueError("invalid source_ip")
    occurred = payload.get("occurred_at")
    if occurred:
        try:
            if isinstance(occurred,str):occurred = datetime.fromisoformat(occurred.replace("Z", "+00:00"))
            if not isinstance(occurred,datetime):raise ValueError()
            if occurred.tzinfo is None: raise ValueError()
            occurred = occurred.astimezone(timezone.utc)
        except (AttributeError, TypeError, ValueError): raise ValueError("occurred_at must be ISO 8601 with timezone")
    else: occurred = datetime.now(timezone.utc)
    metadata = payload.get("metadata", {})
    if not isinstance(metadata, dict): raise ValueError("metadata must be an object")
    try:event_id=str(uuid.UUID(str(payload.get("event_id") or uuid.uuid4())))
    except (ValueError, AttributeError):raise ValueError("event_id must be a UUID")
    if occurred > datetime.now(timezone.utc) + timedelta(minutes=5):raise ValueError("occurred_at cannot be more than five minutes in the future")
    return dict(event_id=event_id, occurred_at=occurred,
        event_type=event_type, source_system=source, source_ip=source_ip,
        username=(str(payload["username"])[:80] if payload.get("username") else None),
        outcome=outcome, severity=severity, description=description, metadata_json=metadata,
        correlation_id=(str(payload["correlation_id"])[:64] if payload.get("correlation_id") else None), simulated=bool(simulated))

def audit(action, target=None, actor_id=None, metadata=None):
    db.session.add(AuditRecord(actor_id=actor_id, action=action, target=target, metadata_json=metadata or {}))

def ingest_event(payload, simulated=False, actor_id=None):
    values = normalize_event(payload, simulated)
    event = SecurityEvent(**values)
    db.session.add(event)
    try:
        db.session.flush()
        audit("event.ingested", event.event_id, actor_id, {"simulated": simulated, "event_type": event.event_type})
        evaluate_rules(event)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        existing = SecurityEvent.query.filter_by(event_id=values["event_id"]).first()
        if existing: return existing, False
        raise
    broadcast_event(event)
    return event, True

def broadcast_event(event):
    from flask import current_app
    payload=serialize_event(event)
    from .models import User
    for (user_id,) in db.session.query(User.id).filter_by(active=True).all():
        current_app.extensions["socketio"].emit("event",payload,namespace="/live",to=f"user:{user_id}")

def evaluate_rules(event):
    if event.event_type != "authentication": return
    now = datetime.now(timezone.utc)

    def configured(rule_id, default_threshold, default_window):
        rule = db.session.get(DetectionRule, rule_id)
        if rule and not rule.enabled: return None
        return (rule, rule.threshold if rule else default_threshold, rule.window_seconds if rule else default_window)

    def emit(rule_id, name, threshold, window, entity, related, explanation, recommendation, severity="high", trigger=None):
        if not related: return
        trigger=trigger or event
        entity = str(entity)
        correlation=f"{rule_id}:{entity}"
        episode = f"{correlation}:{int(now.timestamp()) // window}"
        if Alert.query.filter_by(correlation_key=correlation).filter(Alert.created_at >= now-timedelta(seconds=window)).first(): return
        mapping = {
            "auth.bruteforce": {"id": "T1110", "name": "Brute Force"},
            "auth.account_failures": {"id": "T1110", "name": "Brute Force"},
            "auth.password_spray": {"id": "T1110.003", "name": "Password Spraying"},
        }.get(rule_id)
        evidence={"threshold": threshold, "observed": len(related), "event_ids": [x.event_id for x in related], "entity_key": entity}
        if mapping:evidence["mitre_attack"]={**mapping,"url":f"https://attack.mitre.org/techniques/{mapping['id'].replace('.', '/')}/"}
        alert = Alert(alert_id=str(uuid.uuid4()), rule_id=rule_id, rule_name=name, severity=severity,
            description=f"{name}: {len(related)} supporting authentication events in {window} seconds.",
            evidence=evidence,
            event_ids=[x.event_id for x in related], source_ip=trigger.source_ip, username=trigger.username,
            window_seconds=window, simulated=trigger.simulated, explanation=explanation,
            recommendation=recommendation, episode_key=episode, correlation_key=correlation)
        try:
            with db.session.begin_nested():
                db.session.add(alert); db.session.flush()
            rule = db.session.get(DetectionRule, rule_id)
            if rule: rule.last_triggered = now
            audit("alert.created", alert.alert_id, metadata={"rule_id": rule_id, "simulated": trigger.simulated})
        except IntegrityError:
            # A concurrent worker may have inserted the same unique episode key.
            return

    if event.outcome == "failure":
        if event.source_ip:
            cfg = configured("auth.bruteforce", 5, 60)
            if cfg:
                _, threshold, window = cfg
                candidates = _auth_rows(event, event.occurred_at - timedelta(seconds=window), "failure", source_ip=event.source_ip, through=event.occurred_at+timedelta(seconds=window))
                rows = _window_containing(event,candidates,window,threshold)
                if rows:
                    emit("auth.bruteforce", "Repeated authentication failures from one source", threshold, window, event.source_ip, rows,
                         f"At least {threshold} failures from one IP occurred in a rolling {window}-second window. This is suspicious behavior, not proof of compromise.",
                         "Review related events and account context; consider rate limiting and MFA under local policy.")
            if event.username:
                cfg = configured("auth.account_failures", 5, 60)
                if cfg:
                    _, threshold, window = cfg
                    candidates = _auth_rows(event, event.occurred_at - timedelta(seconds=window), "failure", username=event.username, through=event.occurred_at+timedelta(seconds=window))
                    rows = _window_containing(event,candidates,window,threshold)
                    if rows:
                        emit("auth.account_failures", "Repeated failures against one account", threshold, window, event.username, rows,
                             f"At least {threshold} failures targeted the same account in {window} seconds, possibly from multiple sources.",
                             "Review account history and source diversity; verify MFA and contact the account owner per policy.")
            cfg = configured("auth.password_spray", 5, 60)
            if cfg:
                _, threshold, window = cfg
                candidates = _auth_rows(event, event.occurred_at - timedelta(seconds=window), "failure", source_ip=event.source_ip, through=event.occurred_at+timedelta(seconds=window))
                rows = _spray_window_containing(event,candidates,window,threshold)
                accounts = {x.username.casefold() for x in rows or [] if x.username}
                if event.source_ip and rows:
                    emit("auth.password_spray", "Password spraying indicator", threshold, window, event.source_ip, rows,
                         f"Failures from one IP touched {len(accounts)} distinct accounts in {window} seconds.",
                         "Review source and account spread, authentication controls, and related network telemetry.")
    if event.username:
        cfg = configured("auth.success_after_failures", 3, 300)
        if cfg:
            _, threshold, window = cfg
            lower=event.occurred_at-timedelta(seconds=window);upper=event.occurred_at+timedelta(seconds=window)
            failures=_auth_rows(event,lower,"failure",username=event.username,through=upper)
            successes=_auth_rows(event,lower,"success",username=event.username,through=upper)
            for success in successes:
                # New failure events can arrive out of chronological order. Only count a late failure
                # when its event time is before a success that falls within its detection window.
                success_time=_as_utc(success.occurred_at)
                event_time=_as_utc(event.occurred_at)
                if event.outcome=="failure" and event_time>success_time:continue
                matching=[failure for failure in failures if success_time-timedelta(seconds=window)<=_as_utc(failure.occurred_at)<=success_time]
                if len(matching)>=threshold and (event.event_id==success.event_id or any(x.event_id==event.event_id for x in matching)):
                    emit("auth.success_after_failures", "Successful login after repeated failures", threshold, window,
                         f"{success.username.casefold()}:{success.source_ip or 'unknown'}", matching+[success],
                         f"A successful authentication followed at least {threshold} failures against the same account within {window} seconds. This does not prove account compromise.",
                         "Verify the successful login with the account owner and review source, device, and MFA context.",trigger=success)
                    break

def _auth_rows(event, start, outcome, source_ip=None, username=None, through=None):
    from sqlalchemy import func
    query = SecurityEvent.query.filter(SecurityEvent.event_type == "authentication", SecurityEvent.outcome == outcome,
        SecurityEvent.simulated == event.simulated, SecurityEvent.occurred_at >= start,
        SecurityEvent.occurred_at <= (through or event.occurred_at))
    if source_ip: query = query.filter(SecurityEvent.source_ip == source_ip)
    if username: query = query.filter(func.lower(SecurityEvent.username) == username.casefold())
    return query.order_by(SecurityEvent.occurred_at, SecurityEvent.id).all()

def _window_containing(event,candidates,window,threshold):
    event_time=_as_utc(event.occurred_at)
    for endpoint in candidates:
        endpoint_time=_as_utc(endpoint.occurred_at)
        if endpoint_time<event_time:continue
        rows=[row for row in candidates if endpoint_time-timedelta(seconds=window)<=_as_utc(row.occurred_at)<=endpoint_time]
        if len(rows)>=threshold and any(row.event_id==event.event_id for row in rows):return rows
    return []

def _spray_window_containing(event,candidates,window,threshold):
    event_time=_as_utc(event.occurred_at)
    for endpoint in candidates:
        endpoint_time=_as_utc(endpoint.occurred_at)
        if endpoint_time<event_time:continue
        rows=[row for row in candidates if endpoint_time-timedelta(seconds=window)<=_as_utc(row.occurred_at)<=endpoint_time]
        accounts={row.username.casefold() for row in rows if row.username}
        if len(accounts)>=threshold and any(row.event_id==event.event_id for row in rows):return rows
    return []

def _as_utc(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)

def serialize_event(e):
    return {"event_id":e.event_id,"cursor":e.id,"occurred_at":e.occurred_at.isoformat(),"event_type":e.event_type,"source_ip":e.source_ip,"username":e.username,"outcome":e.outcome,"severity":e.severity,"description":e.description,"simulated":e.simulated,"import_record_id":e.import_record_id}

def parse_auth_line(line):
    """Parse documented CSV: ISO8601,event_type,source_ip,username,outcome,description"""
    import csv
    try:row = next(csv.reader([line]))
    except csv.Error as exc:raise ValueError("Malformed CSV quoting") from exc
    if len(row) != 6: raise ValueError("Expected six CSV fields")
    stamp, event_type, ip, username, outcome, description = row
    if event_type.strip()!="authentication":raise ValueError("Only authentication records are supported by this parser")
    if outcome not in {"success","failure"}:raise ValueError("Authentication outcome must be success or failure")
    if not stamp.strip():raise ValueError("Timestamp is required")
    return {"occurred_at":stamp,"event_type":event_type,"source_system":"csv-import","source_ip":ip or None,"username":username or None,"outcome":outcome or None,"description":description}
