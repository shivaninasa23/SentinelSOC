import csv, io, uuid
import re
from datetime import datetime, timezone, timedelta, date, time
from flask import Blueprint, render_template, jsonify, request, g, Response, abort
from .extensions import db
from .models import SecurityEvent, Alert, Incident, IncidentAlert, InvestigationNote, DetectionRule, AuditRecord, User, EventImport
from .auth import login_required, roles_required
from .services import audit, serialize_event

main_bp = Blueprint("main", __name__)

@main_bp.get("/")
@login_required
def dashboard(): return render_template("dashboard.html", user=g.user)

@main_bp.get("/<page>")
@login_required
def page(page):
    allowed={"events","alerts","incidents","rules","audit","reports","users","settings","threat-intel"}
    if page not in allowed: abort(404)
    if page == "users" and g.user.role != "admin": abort(403)
    return render_template("page.html", user=g.user, page=page)

@main_bp.get("/event/<event_id>")
@login_required
def event_detail(event_id):
    e=SecurityEvent.query.filter_by(event_id=event_id).first_or_404()
    return render_template("detail.html", user=g.user, item=serialize_event(e), kind="Event")

@main_bp.get("/alert/<alert_id>")
@login_required
def alert_detail(alert_id):
    a=Alert.query.filter_by(alert_id=alert_id).first_or_404()
    assignee=db.session.get(User,a.assigned_to) if a.assigned_to else None
    return render_template("detail.html", user=g.user, item={"id":a.alert_id,"rule":a.rule_name,"severity":a.severity,"status":a.status,"simulated":a.simulated,"assigned_to":assignee.username if assignee else None,"description":a.description,"evidence":a.evidence,"event_ids":a.event_ids,"source_ip":a.source_ip,"explanation":a.explanation,"recommendation":a.recommendation}, kind="Alert")

@main_bp.get("/incident/<incident_id>")
@login_required
def incident_detail(incident_id):
    i=Incident.query.filter_by(incident_id=incident_id).first_or_404()
    notes=InvestigationNote.query.filter_by(incident_id=i.id).order_by(InvestigationNote.created_at.desc()).all()
    assignee=db.session.get(User,i.assigned_to) if i.assigned_to else None
    alert_links=IncidentAlert.query.filter_by(incident_id=i.id).all()
    alert_rows=[db.session.get(Alert,link.alert_id) for link in alert_links]
    alert_ids=[alert.alert_id for alert in alert_rows if alert]
    event_ids={event_id for alert in alert_rows if alert for event_id in (alert.event_ids or [])}
    timeline=[serialize_event(e) for e in SecurityEvent.query.filter(SecurityEvent.event_id.in_(event_ids)).order_by(SecurityEvent.occurred_at).all()] if event_ids else []
    return render_template("detail.html", user=g.user, item={"id":i.incident_id,"title":i.title,"severity":i.severity,"status":i.status,"simulated":i.simulated,"assigned_to":assignee.username if assignee else None,"resolution_notes":i.resolution_notes,"notes":[{"body":n.body,"created_at":n.created_at.isoformat()} for n in notes],"alerts":alert_ids,"timeline":timeline}, kind="Incident")

@main_bp.post("/api/alert/<alert_id>/status")
@login_required
def alert_status(alert_id):
    a=Alert.query.filter_by(alert_id=alert_id).first_or_404(); status=(request.get_json(silent=True) or {}).get("status")
    if status not in {"open","acknowledged","resolved"}: return jsonify(error="Invalid status"),400
    a.status=status; audit("alert.status_changed", a.alert_id, g.user.id,{"status":status}); db.session.commit()
    return jsonify(status=status)

@main_bp.post("/api/alert/<alert_id>/assign")
@login_required
def alert_assign(alert_id):
    alert=Alert.query.filter_by(alert_id=alert_id).first_or_404();data=request.get_json(silent=True) or {};assignee=data.get("assigned_to")
    if assignee is not None:
        try:assignee=int(assignee)
        except (ValueError,TypeError):return jsonify(error="assigned_to must identify an active analyst or administrator."),400
        user=db.session.get(User,assignee)
        if not user or not user.active or user.role not in {"analyst","admin"}:return jsonify(error="Assignee is unavailable."),400
    alert.assigned_to=assignee;audit("alert.assigned",alert.alert_id,g.user.id,{"assigned_to":assignee});db.session.commit()
    return jsonify(assigned_to=assignee)

@main_bp.post("/api/alert/<alert_id>/incident")
@login_required
def alert_to_incident(alert_id):
    a=Alert.query.filter_by(alert_id=alert_id).first_or_404()
    if a.incident_id: return jsonify(incident_id=Incident.query.get(a.incident_id).incident_id)
    i=Incident(incident_id=str(uuid.uuid4()),title=a.rule_name+" — "+(a.source_ip or "source unknown"),severity=a.severity,simulated=a.simulated)
    db.session.add(i); db.session.flush(); a.incident_id=i.id
    db.session.add(IncidentAlert(incident_id=i.id,alert_id=a.id,linked_by=g.user.id))
    audit("incident.created_from_alert",i.incident_id,g.user.id,{"alert_id":a.alert_id}); db.session.commit()
    return jsonify(incident_id=i.incident_id),201

@main_bp.post("/api/incidents")
@login_required
def incident_create():
    data=request.get_json(silent=True) or {};title=str(data.get("title","")).strip();severity=data.get("severity","medium")
    if not title or len(title)>200:return jsonify(error="Incident title is required and must be at most 200 characters."),400
    if severity not in {"critical","high","medium","low"}:return jsonify(error="Invalid severity."),400
    incident=Incident(incident_id=str(uuid.uuid4()),title=title,severity=severity,simulated=False)
    db.session.add(incident);db.session.flush();audit("incident.created",incident.incident_id,g.user.id,{"severity":severity});db.session.commit()
    return jsonify(incident_id=incident.incident_id),201

@main_bp.get("/api/incident/<incident_id>")
@login_required
def incident_read(incident_id):
    incident=Incident.query.filter_by(incident_id=incident_id).first_or_404()
    links=IncidentAlert.query.filter_by(incident_id=incident.id).all();alerts=[db.session.get(Alert,x.alert_id) for x in links]
    event_ids={event_id for alert in alerts if alert for event_id in (alert.event_ids or [])}
    events=SecurityEvent.query.filter(SecurityEvent.event_id.in_(event_ids)).order_by(SecurityEvent.occurred_at).all() if event_ids else []
    notes=InvestigationNote.query.filter_by(incident_id=incident.id).order_by(InvestigationNote.created_at).all()
    assignee=db.session.get(User,incident.assigned_to) if incident.assigned_to else None
    timeline=[{"kind":"event",**serialize_event(e)} for e in events]
    timeline.extend({"kind":"note","created_at":n.created_at.isoformat(),"author":db.session.get(User,n.author_id).username,"body":n.body} for n in notes)
    timeline.sort(key=lambda x:x.get("occurred_at",x.get("created_at","")))
    return jsonify(incident={"incident_id":incident.incident_id,"title":incident.title,"severity":incident.severity,"status":incident.status,"simulated":incident.simulated,"assigned_to":assignee.username if assignee else None,"resolution_notes":incident.resolution_notes,"alerts":[{"alert_id":a.alert_id,"rule_name":a.rule_name,"simulated":a.simulated} for a in alerts if a],"timeline":timeline})

@main_bp.post("/api/incident/<incident_id>/assign")
@login_required
def incident_assign(incident_id):
    incident=Incident.query.filter_by(incident_id=incident_id).first_or_404();data=request.get_json(silent=True) or {};assignee=data.get("assigned_to")
    if assignee is not None:
        try:assignee=int(assignee)
        except (ValueError,TypeError):return jsonify(error="Invalid assignee."),400
        user=db.session.get(User,assignee)
        if not user or not user.active or user.role not in {"analyst","admin"}:return jsonify(error="Assignee is unavailable."),400
    incident.assigned_to=assignee;audit("incident.assigned",incident.incident_id,g.user.id,{"assigned_to":assignee});db.session.commit()
    return jsonify(assigned_to=assignee)

@main_bp.post("/api/incident/<incident_id>/alerts")
@login_required
def incident_link_alert(incident_id):
    incident=Incident.query.filter_by(incident_id=incident_id).first_or_404();data=request.get_json(silent=True) or {};alert=Alert.query.filter_by(alert_id=data.get("alert_id","")).first()
    if not alert:return jsonify(error="Alert not found."),404
    if alert.simulated != incident.simulated:return jsonify(error="Observed and simulated records cannot be linked together."),400
    if alert.incident_id and alert.incident_id!=incident.id:return jsonify(error="Alert is already linked to another incident."),409
    if IncidentAlert.query.filter_by(incident_id=incident.id,alert_id=alert.id).first():return jsonify(error="Alert is already linked."),409
    db.session.add(IncidentAlert(incident_id=incident.id,alert_id=alert.id,linked_by=g.user.id));alert.incident_id=incident.id
    audit("incident.alert_linked",incident.incident_id,g.user.id,{"alert_id":alert.alert_id});db.session.commit()
    return jsonify(linked=True),201

@main_bp.post("/api/incident/<incident_id>/update")
@login_required
def incident_update(incident_id):
    i=Incident.query.filter_by(incident_id=incident_id).first_or_404(); data=request.json or {}
    if "status" in data:
        status=data["status"]
        if status not in {"open","investigating","resolved","closed"}: return jsonify(error="Invalid status"),400
        if i.status in {"resolved","closed"} and status in {"open","investigating"} and g.user.role!="admin":return jsonify(error="Only an administrator may reopen a resolved incident."),403
        if status in {"resolved","closed"} and not (data.get("resolution_notes") or i.resolution_notes):return jsonify(error="Resolution notes are required before resolution or closure."),400
        i.status=status
        if status in {"resolved","closed"} and not i.resolved_at:i.resolved_at=datetime.now(timezone.utc)
        if status in {"open","investigating"}:i.resolved_at=None
    if "resolution_notes" in data: i.resolution_notes=str(data["resolution_notes"]).strip()[:5000]
    if data.get("note"):
        body=str(data["note"]).strip()
        if not body or len(body)>5000:return jsonify(error="Notes must contain 1 to 5000 characters."),400
        db.session.add(InvestigationNote(incident_id=i.id,author_id=g.user.id,body=body))
    audit("incident.updated",i.incident_id,g.user.id,{"status":i.status}); db.session.commit()
    return jsonify(status=i.status)

@main_bp.get("/api/export/incident/<incident_id>.html")
@login_required
def incident_report(incident_id):
    incident=Incident.query.filter_by(incident_id=incident_id).first_or_404()
    links=IncidentAlert.query.filter_by(incident_id=incident.id).all();alerts=[db.session.get(Alert,x.alert_id) for x in links]
    event_ids={event_id for alert in alerts if alert for event_id in (alert.event_ids or [])}
    events=SecurityEvent.query.filter(SecurityEvent.event_id.in_(event_ids)).order_by(SecurityEvent.occurred_at).all() if event_ids else []
    notes=InvestigationNote.query.filter_by(incident_id=incident.id).order_by(InvestigationNote.created_at).all()
    audit("report.incident_exported",incident.incident_id,g.user.id);db.session.commit()
    content=render_template("incident_report.html",incident=incident,alerts=[a for a in alerts if a],events=events,notes=notes)
    return Response(content,mimetype="text/html",headers={"Content-Disposition":f"attachment; filename=incident-{incident.incident_id}.html"})

@main_bp.post("/api/rule/<rule_id>")
@roles_required("admin")
def rule_update(rule_id):
    r=db.session.get(DetectionRule,rule_id)
    if not r: abort(404)
    d=request.json or {}
    if "threshold" in d and (not isinstance(d["threshold"],int) or not 2<=d["threshold"]<=100): return jsonify(error="threshold must be between 2 and 100"),400
    if "window_seconds" in d and (not isinstance(d["window_seconds"],int) or not 10<=d["window_seconds"]<=3600): return jsonify(error="window_seconds must be between 10 and 3600"),400
    if "enabled" in d and not isinstance(d["enabled"],bool):return jsonify(error="enabled must be a boolean."),400
    if "threshold" in d:r.threshold=d["threshold"]
    if "window_seconds" in d:r.window_seconds=d["window_seconds"]
    if "enabled" in d:
        r.enabled=d["enabled"]
    audit("rule.updated",r.id,g.user.id,{"threshold":r.threshold,"window_seconds":r.window_seconds,"enabled":r.enabled});db.session.commit()
    return jsonify(enabled=r.enabled,threshold=r.threshold,window_seconds=r.window_seconds)

@main_bp.post("/api/users")
@roles_required("admin")
def user_create():
    data=request.get_json(silent=True) or {};username=str(data.get("username","")).strip();password=data.get("password","");role=data.get("role","analyst")
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{3,80}",username):return jsonify(error="Username must be 3–80 letters, numbers, or . _ @ - characters."),400
    if role not in {"analyst","admin"}:return jsonify(error="Role must be analyst or admin."),400
    if not isinstance(password,str) or len(password)<12 or len(password)>256:return jsonify(error="Password must be 12–256 characters."),400
    if User.query.filter_by(username=username).first():return jsonify(error="Username is already in use."),409
    user=User(username=username,role=role);user.set_password(password);db.session.add(user);db.session.flush()
    audit("user.created",username,g.user.id,{"role":role});db.session.commit()
    return jsonify(user={"id":user.id,"username":user.username,"role":user.role,"active":user.active}),201

@main_bp.put("/api/users/<int:user_id>")
@roles_required("admin")
def user_update(user_id):
    user=db.session.get(User,user_id)
    if not user:abort(404)
    data=request.get_json(silent=True) or {};old={"role":user.role,"active":user.active};changed={}
    role=data.get("role",user.role);active=data.get("active",user.active)
    if role not in {"analyst","admin"}:return jsonify(error="Role must be analyst or admin."),400
    if not isinstance(active,bool):return jsonify(error="active must be a boolean."),400
    if "password" in data and (not isinstance(data["password"],str) or not 12<=len(data["password"])<=256):
        return jsonify(error="Password must be 12–256 characters."),400
    if user.id==g.user.id and (not active or role!="admin"):
        return jsonify(error="You cannot deactivate or demote your own administrator account."),400
    if old["role"]=="admin" and old["active"] and (role!="admin" or not active):
        if User.query.filter_by(role="admin",active=True).count()<=1:
            return jsonify(error="At least one active administrator must remain."),400
    user.role,user.active=role,active
    if "password" in data:
        user.set_password(data["password"]);changed["password_reset"]=True
    changed.update({"role":user.role,"active":user.active});audit("user.updated",user.username,g.user.id,changed);db.session.commit()
    return jsonify(user={"id":user.id,"username":user.username,"role":user.role,"active":user.active})

@main_bp.get("/api/export/events.csv")
@login_required
def export_events():
    query=filtered_events();count=query.count()
    output=io.StringIO(); w=csv.writer(output); w.writerow(["event_id","occurred_at","event_type","source_ip","username","outcome","severity","description","simulated","import_record_id"])
    for e in query.order_by(SecurityEvent.occurred_at.desc()).limit(10000):
        vals=[e.event_id,e.occurred_at.isoformat(),e.event_type,e.source_ip,e.username,e.outcome,e.severity,e.description,e.simulated,e.import_record_id]
        w.writerow([csv_safe(value) for value in vals])
    audit("report.events_exported",metadata={"rows":min(count,10000),"filters":dict(request.args)},actor_id=g.user.id);db.session.commit()
    return Response(output.getvalue(),mimetype="text/csv",headers={"Content-Disposition":"attachment; filename=events.csv"})

@main_bp.get("/api/export/alerts.csv")
@login_required
def export_alerts():
    query=Alert.query
    for key in ("status","severity","rule_id"):
        if request.args.get(key):query=query.filter(getattr(Alert,key)==request.args[key][:80])
    if request.args.get("simulated") in {"true","false"}:query=query.filter_by(simulated=request.args["simulated"]=="true")
    output=io.StringIO();writer=csv.writer(output);writer.writerow(["alert_id","rule_id","severity","created_at","status","source_ip","username","assigned_to","simulated","description"])
    rows=query.order_by(Alert.created_at.desc()).limit(10000).all()
    for a in rows:
        assignee=db.session.get(User,a.assigned_to) if a.assigned_to else None
        writer.writerow([csv_safe(v) for v in [a.alert_id,a.rule_id,a.severity,a.created_at.isoformat(),a.status,a.source_ip,a.username,assignee.username if assignee else None,a.simulated,a.description]])
    audit("report.alerts_exported",metadata={"rows":len(rows),"filters":dict(request.args)},actor_id=g.user.id);db.session.commit()
    return Response(output.getvalue(),mimetype="text/csv",headers={"Content-Disposition":"attachment; filename=alerts.csv"})

def filtered_events():
    query=SecurityEvent.query
    for key in ("outcome","source_ip","event_type"):
        if request.args.get(key):query=query.filter(getattr(SecurityEvent,key)==request.args[key][:128])
    if request.args.get("simulated") in {"true","false"}:query=query.filter_by(simulated=request.args["simulated"]=="true")
    if request.args.get("q"):
        from sqlalchemy import or_
        term=f"%{request.args['q'][:80]}%";query=query.filter(or_(SecurityEvent.username.ilike(term),SecurityEvent.description.ilike(term),SecurityEvent.source_ip.ilike(term)))
    try:
        if request.args.get("from"):
            start=date.fromisoformat(request.args["from"]);query=query.filter(SecurityEvent.occurred_at>=datetime.combine(start,time.min,tzinfo=timezone.utc))
        if request.args.get("to"):
            end=date.fromisoformat(request.args["to"])+timedelta(days=1);query=query.filter(SecurityEvent.occurred_at<datetime.combine(end,time.min,tzinfo=timezone.utc))
    except ValueError:abort(400,description="Date filters must use YYYY-MM-DD.")
    return query

def csv_safe(value):
    if not isinstance(value,str):return value
    first=value.lstrip(" \t\r\n")[:1]
    return "'"+value if first in {"=","+","-","@"} else value
