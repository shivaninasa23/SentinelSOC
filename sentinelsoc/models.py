from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from .extensions import db

def utcnow(): return datetime.now(timezone.utc)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="analyst")
    active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    def set_password(self, password): self.password_hash = generate_password_hash(password, method="scrypt")
    def check_password(self, password): return check_password_hash(self.password_hash, password)

class EventImport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    import_id = db.Column(db.String(36), unique=True, nullable=False, index=True)
    filename = db.Column(db.String(255), nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    total_lines = db.Column(db.Integer, nullable=False)
    imported_count = db.Column(db.Integer, nullable=False)
    duplicate_count = db.Column(db.Integer, nullable=False)
    malformed_count = db.Column(db.Integer, nullable=False)

class SecurityEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.String(36), unique=True, nullable=False, index=True)
    occurred_at = db.Column(db.DateTime(timezone=True), nullable=False, index=True)
    ingested_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    event_type = db.Column(db.String(64), nullable=False, index=True)
    source_system = db.Column(db.String(128), nullable=False)
    source_ip = db.Column(db.String(45), index=True)
    username = db.Column(db.String(80), index=True)
    outcome = db.Column(db.String(16), index=True)
    severity = db.Column(db.String(16), nullable=False, default="low")
    description = db.Column(db.String(500), nullable=False)
    metadata_json = db.Column(db.JSON, nullable=False, default=dict)
    correlation_id = db.Column(db.String(64))
    simulated = db.Column(db.Boolean, nullable=False, default=False, index=True)
    import_record_id = db.Column(db.Integer, db.ForeignKey("event_import.id", name="fk_security_event_import_record_id"), index=True)

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.String(36), unique=True, nullable=False, index=True)
    rule_id = db.Column(db.String(80), nullable=False, index=True)
    rule_name = db.Column(db.String(160), nullable=False)
    severity = db.Column(db.String(16), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    description = db.Column(db.String(500), nullable=False)
    evidence = db.Column(db.JSON, nullable=False, default=dict)
    event_ids = db.Column(db.JSON, nullable=False, default=list)
    source_ip = db.Column(db.String(45), index=True)
    username = db.Column(db.String(80))
    window_seconds = db.Column(db.Integer, nullable=False)
    explanation = db.Column(db.String(1000), nullable=False)
    recommendation = db.Column(db.String(1000), nullable=False)
    status = db.Column(db.String(24), nullable=False, default="open", index=True)
    simulated = db.Column(db.Boolean, nullable=False, default=False, index=True)
    assigned_to = db.Column(db.Integer, db.ForeignKey("user.id"))
    incident_id = db.Column(db.Integer, db.ForeignKey("incident.id"))
    episode_key = db.Column(db.String(200), unique=True, nullable=False)
    correlation_key = db.Column(db.String(240), index=True)

class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.String(36), unique=True, nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    severity = db.Column(db.String(16), nullable=False)
    status = db.Column(db.String(24), nullable=False, default="open", index=True)
    simulated = db.Column(db.Boolean, nullable=False, default=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey("user.id"))
    resolution_notes = db.Column(db.Text)
    resolved_at = db.Column(db.DateTime(timezone=True))

class IncidentAlert(db.Model):
    __table_args__ = (db.UniqueConstraint("incident_id", "alert_id", name="uq_incident_alert"),)
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey("incident.id"), nullable=False, index=True)
    alert_id = db.Column(db.Integer, db.ForeignKey("alert.id"), nullable=False, index=True)
    linked_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

class InvestigationNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey("incident.id"), nullable=False, index=True)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    author = db.relationship("User", foreign_keys=[author_id])

class AuditRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    action = db.Column(db.String(80), nullable=False, index=True)
    target = db.Column(db.String(160))
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    metadata_json = db.Column(db.JSON, nullable=False, default=dict)

class DetectionRule(db.Model):
    id = db.Column(db.String(80), primary_key=True)
    name = db.Column(db.String(160), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    threshold = db.Column(db.Integer, nullable=False, default=5)
    window_seconds = db.Column(db.Integer, nullable=False, default=60)
    last_triggered = db.Column(db.DateTime(timezone=True))

class ThreatIntelCache(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    provider = db.Column(db.String(80), nullable=False)
    indicator = db.Column(db.String(128), nullable=False)
    status = db.Column(db.String(24), nullable=False)
    result_json = db.Column(db.JSON, nullable=False, default=dict)
    fetched_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False, index=True)
    __table_args__ = (db.UniqueConstraint("provider", "indicator", name="uq_threat_provider_indicator"),)
