from flask import Blueprint, request, jsonify, g, current_app
from sqlalchemy import or_
from .auth import login_required
from .models import SecurityEvent, Alert, Incident, DetectionRule, AuditRecord, User, EventImport
from .extensions import db
from .services import ingest_event, serialize_event
from . import limiter, csrf

api_bp=Blueprint("api",__name__)

@api_bp.get("/dashboard")
@login_required
def dashboard_data():
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import func
    cutoff=datetime.now(timezone.utc)-timedelta(hours=24)
    observed=SecurityEvent.query.filter_by(simulated=False)
    observed_recent=observed.filter(SecurityEvent.occurred_at>=cutoff)
    sources=db.session.query(SecurityEvent.source_ip,func.count(SecurityEvent.id).label("count")).filter(
        SecurityEvent.simulated.is_(False),SecurityEvent.event_type=="authentication",SecurityEvent.outcome=="failure",
        SecurityEvent.source_ip.is_not(None),SecurityEvent.occurred_at>=cutoff).group_by(SecurityEvent.source_ip).order_by(func.count(SecurityEvent.id).desc()).limit(5).all()
    return jsonify(
        total_events=observed.count(),simulated_events=SecurityEvent.query.filter_by(simulated=True).count(),
        events_24h=observed_recent.count(),failed_auth=observed_recent.filter_by(event_type="authentication",outcome="failure").count(),
        active_incidents=Incident.query.filter_by(simulated=False).filter(Incident.status.in_(["open","investigating"])).count(),
        alerts=[{"alert_id":a.alert_id,"rule_name":a.rule_name,"severity":a.severity,"status":a.status,"simulated":a.simulated,"created_at":a.created_at.isoformat()} for a in Alert.query.order_by(Alert.created_at.desc()).limit(8)],
        events=[serialize_event(e) for e in SecurityEvent.query.order_by(SecurityEvent.occurred_at.desc()).limit(12)],
        sources=[{"source_ip":ip,"failures":count} for ip,count in sources],
        incidents=[{"incident_id":i.incident_id,"title":i.title,"severity":i.severity,"status":i.status,"simulated":i.simulated,"created_at":i.created_at.isoformat()} for i in Incident.query.order_by(Incident.created_at.desc()).limit(5)],
        rules=[{"id":r.id,"name":r.name,"enabled":r.enabled,"threshold":r.threshold,"window_seconds":r.window_seconds,"last_triggered":r.last_triggered.isoformat() if r.last_triggered else None} for r in DetectionRule.query.order_by(DetectionRule.id)])

@api_bp.route("/events",methods=["GET","POST"])
@login_required
def events():
    if request.method=="POST":
        try:
            e,created=ingest_event(request.get_json(silent=True),actor_id=g.user.id)
            return jsonify(event=serialize_event(e),created=created),201 if created else 200
        except ValueError as ex:return jsonify(error=str(ex)),400
    q=SecurityEvent.query
    if request.args.get("outcome"):q=q.filter_by(outcome=request.args["outcome"])
    if request.args.get("source_ip"):q=q.filter_by(source_ip=request.args["source_ip"])
    if request.args.get("simulated") in {"true","false"}:q=q.filter_by(simulated=request.args["simulated"]=="true")
    if request.args.get("event_type"):q=q.filter_by(event_type=request.args["event_type"][:64])
    if request.args.get("q"):
        term=f"%{request.args['q'][:80]}%"
        q=q.filter(or_(SecurityEvent.username.ilike(term),SecurityEvent.description.ilike(term),SecurityEvent.source_ip.ilike(term)))
    after_id=request.args.get("after_id",type=int)
    if after_id is not None:q=q.filter(SecurityEvent.id>max(0,after_id))
    limit=min(max(request.args.get("limit",50,type=int),1),200);offset=max(request.args.get("offset",0,type=int),0)
    ordering=SecurityEvent.id.asc() if after_id is not None or request.args.get("order")=="asc" else SecurityEvent.occurred_at.desc()
    return jsonify(events=[serialize_event(e) for e in q.order_by(ordering).offset(offset).limit(limit)],total=q.count(),limit=limit,offset=offset)

@api_bp.post("/imports/preview")
@login_required
def import_preview():
    from .log_imports import preview_upload
    file=request.files.get("file")
    if not file:return jsonify(error="Select a CSV file."),400
    try:return jsonify(preview_upload(file))
    except ValueError as exc:return jsonify(error=str(exc)),400

@api_bp.post("/imports")
@login_required
def import_events():
    from .log_imports import import_upload
    file=request.files.get("file")
    if not file:return jsonify(error="Select a CSV file."),400
    try:return jsonify(import_upload(file,g.user.id)),201
    except ValueError as exc:return jsonify(error=str(exc)),400

@api_bp.get("/imports")
@login_required
def imports():
    records=EventImport.query.order_by(EventImport.created_at.desc()).limit(100).all()
    return jsonify(imports=[{"import_id":i.import_id,"filename":i.filename,"created_at":i.created_at.isoformat(),"total_lines":i.total_lines,"imported":i.imported_count,"duplicates":i.duplicate_count,"malformed":i.malformed_count} for i in records])

@api_bp.get("/alerts")
@login_required
def alerts():
    q=Alert.query
    if request.args.get("status"):q=q.filter_by(status=request.args["status"])
    if request.args.get("severity"):q=q.filter_by(severity=request.args["severity"])
    if request.args.get("simulated") in {"true","false"}:q=q.filter_by(simulated=request.args["simulated"]=="true")
    if request.args.get("q"):
        term=f"%{request.args['q'][:80]}%";q=q.filter(or_(Alert.rule_name.ilike(term),Alert.description.ilike(term),Alert.source_ip.ilike(term),Alert.username.ilike(term)))
    limit=min(max(request.args.get("limit",50,type=int),1),200);offset=max(request.args.get("offset",0,type=int),0)
    rows=q.order_by(Alert.created_at.desc()).offset(offset).limit(limit).all()
    return jsonify(alerts=[{"alert_id":a.alert_id,"rule_id":a.rule_id,"rule_name":a.rule_name,"severity":a.severity,"status":a.status,"source_ip":a.source_ip,"username":a.username,"assigned_to":db.session.get(User,a.assigned_to).username if a.assigned_to and db.session.get(User,a.assigned_to) else None,"simulated":a.simulated,"created_at":a.created_at.isoformat()} for a in rows],total=q.count(),limit=limit,offset=offset)

@api_bp.get("/incidents")
@login_required
def incidents():
    q=Incident.query
    if request.args.get("status"):q=q.filter_by(status=request.args["status"])
    if request.args.get("severity"):q=q.filter_by(severity=request.args["severity"])
    if request.args.get("simulated") in {"true","false"}:q=q.filter_by(simulated=request.args["simulated"]=="true")
    if request.args.get("q"):
        term=f"%{request.args['q'][:80]}%";q=q.filter(or_(Incident.title.ilike(term),Incident.resolution_notes.ilike(term)))
    limit=min(max(request.args.get("limit",50,type=int),1),200);offset=max(request.args.get("offset",0,type=int),0)
    rows=q.order_by(Incident.created_at.desc()).offset(offset).limit(limit).all()
    return jsonify(incidents=[{"incident_id":i.incident_id,"title":i.title,"severity":i.severity,"status":i.status,"simulated":i.simulated,"assigned_to":db.session.get(User,i.assigned_to).username if i.assigned_to and db.session.get(User,i.assigned_to) else None,"created_at":i.created_at.isoformat(),"resolved_at":i.resolved_at.isoformat() if i.resolved_at else None} for i in rows],total=q.count(),limit=limit,offset=offset)

@api_bp.get("/analytics")
@login_required
def analytics_data():
    from .analytics import analytics
    try:
        days=request.args.get("days",7,type=int)
        if not 1<=days<=91:return jsonify(error="days must be 1–91."),400
        return jsonify(analytics(days=days,start=request.args.get("start"),end=request.args.get("end"),simulated=request.args.get("simulated")=="true"))
    except ValueError as exc:return jsonify(error=str(exc)),400

@api_bp.get("/threat-intel")
@login_required
@limiter.limit("20 per minute")
def threat_intel():
    from .threat_intel import enrich_ip
    from .services import audit
    indicator=request.args.get("ip","")
    try:
        result=enrich_ip(indicator)
        audit("threat_intel.lookup",result["indicator"],g.user.id,{"provider":result["provider"],"status":result["status"],"cached":result["cached"]});db.session.commit()
        return jsonify(result)
    except ValueError as exc:return jsonify(error=str(exc)),400

@api_bp.post("/demo")
@login_required
def demo():
    import ipaddress
    scenario=(request.json or {}).get("scenario")
    if scenario not in {"normal","single","bruteforce","spray","success-after"}:return jsonify(error="Unsupported scenario"),400
    source="127.0.0.1"
    rows=[]
    if scenario=="normal": rows=[("demo-user","success")]
    elif scenario=="single": rows=[("demo-user","failure")]
    elif scenario=="bruteforce": rows=[("demo-user","failure") for _ in range(5)]
    elif scenario=="spray": rows=[(f"demo-user-{i}","failure") for i in range(5)]
    else: rows=[("demo-user","failure") for _ in range(4)]+[("demo-user","success")]
    created=0
    for username,outcome in rows:
        _,fresh=ingest_event({"event_type":"authentication","source_system":"sentinelsoc-demo","source_ip":source,"username":username,"outcome":outcome,"description":f"Demonstration authentication {outcome}"},simulated=True,actor_id=g.user.id)
        created+=int(fresh)
    alerts_count=Alert.query.filter(Alert.source_ip==source,Alert.created_at>=__import__("datetime").datetime.now(__import__("datetime").timezone.utc)-__import__("datetime").timedelta(minutes=1)).count()
    return jsonify(created=created,alerts=alerts_count,simulated=True)

@api_bp.get("/rules")
@login_required
def rules():
    rows=DetectionRule.query.all()
    return jsonify(rules=[{"id":r.id,"name":r.name,"description":r.description,"enabled":r.enabled,"threshold":r.threshold,"window_seconds":r.window_seconds,"last_triggered":r.last_triggered.isoformat() if r.last_triggered else None} for r in rows])

@api_bp.get("/users")
@login_required
def users():
    if g.user.role!="admin":return jsonify(error="Forbidden"),403
    return jsonify(users=[{"id":u.id,"username":u.username,"role":u.role,"active":u.active,"created_at":u.created_at.isoformat()} for u in User.query.order_by(User.username)])

@api_bp.get("/assignees")
@login_required
def assignees():
    return jsonify(users=[{"id":u.id,"username":u.username,"role":u.role} for u in User.query.filter_by(active=True).filter(User.role.in_(["analyst","admin"])).order_by(User.username)])

@api_bp.get("/audit")
@login_required
def audit_records():
    return jsonify(records=[{"action":x.action,"target":x.target,"created_at":x.created_at.isoformat(),"actor_id":x.actor_id,"metadata":x.metadata_json} for x in AuditRecord.query.order_by(AuditRecord.created_at.desc()).limit(200)])

@api_bp.get("/health")
def health():
    try:db.session.execute(db.text("SELECT 1"));status="ok"
    except Exception as exc:
        db.session.rollback();current_app.logger.warning("Health database check failed: %s",type(exc).__name__);status="degraded"
    provider="configured" if current_app.config.get("OTX_API_KEY") else "not_configured"
    return jsonify(status=status,database=status,ingestion="available",threat_intelligence=provider),200 if status=="ok" else 503

@api_bp.post("/ingest")
@csrf.exempt
@limiter.limit("60 per minute")
def ingest():
    token=request.headers.get("X-Ingest-Token","")
    expected=current_app.config.get("INGEST_TOKEN","")
    import hmac
    if not expected or not hmac.compare_digest(token,expected):return jsonify(error="Unauthorized"),401
    try:e,created=ingest_event(request.get_json(silent=True))
    except ValueError as ex:return jsonify(error=str(ex)),400
    return jsonify(event_id=e.event_id,created=created),201 if created else 200

def socket_connect(auth=None):
    from flask import session
    from flask_socketio import join_room
    user=db.session.get(User,session.get("user_id")) if session.get("user_id") else None
    if not user or not user.active:return False
    join_room(f"user:{user.id}")
