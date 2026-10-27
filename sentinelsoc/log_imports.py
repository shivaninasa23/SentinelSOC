"""Bounded, in-memory import of the documented six-column authentication CSV."""
import hashlib
import uuid
from datetime import datetime, timezone
from werkzeug.utils import secure_filename
from .extensions import db
from .models import SecurityEvent, EventImport
from .services import parse_auth_line, normalize_event, evaluate_rules, audit, broadcast_event

MAX_IMPORT_ROWS = 10_000

def fingerprint(values):
    occurred=values.get("occurred_at")
    if isinstance(occurred,str):
        try:occurred=datetime.fromisoformat(occurred.replace("Z","+00:00"))
        except ValueError:pass
    if isinstance(occurred,datetime):
        if occurred.tzinfo is None: occurred=occurred.replace(tzinfo=timezone.utc)
        occurred=occurred.astimezone(timezone.utc).isoformat()
    content = "\x1f".join(str((occurred if k=="occurred_at" else values.get(k)) or "") for k in
        ("occurred_at", "event_type", "source_ip", "username", "outcome", "description"))
    return hashlib.sha256(content.encode("utf-8")).hexdigest()

def parse_upload(file_storage):
    name = secure_filename(file_storage.filename or "")
    if not name or not name.lower().endswith(".csv"):
        raise ValueError("Upload a .csv file using the documented six-column format.")
    raw = file_storage.stream.read(1_048_577)
    if len(raw) > 1_048_576: raise ValueError("CSV upload exceeds 1 MB.")
    try: text = raw.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError: raise ValueError("CSV must be UTF-8 encoded.")
    lines = text.splitlines()
    if len(lines) > MAX_IMPORT_ROWS: raise ValueError(f"CSV may contain at most {MAX_IMPORT_ROWS} rows.")
    if not any(line.strip() for line in lines):raise ValueError("CSV contains no event rows.")
    parsed=[]; errors=[]; seen=set(); duplicates=0
    for line_number, line in enumerate(lines, 1):
        if not line.strip(): continue
        try:
            payload=parse_auth_line(line)
            values=normalize_event(payload)
            payload.update(values)
            key=fingerprint(payload)
            if key in seen:
                duplicates += 1
            else:
                seen.add(key)
                parsed.append((payload,key))
        except (ValueError, TypeError) as exc:
            errors.append({"line":line_number,"error":str(exc)[:160]})
    # Compare imports against retained imported events as part of preview and commit.
    existing=set()
    if parsed:
        for event in SecurityEvent.query.filter_by(source_system="csv-import",simulated=False).all():
            values={"occurred_at":event.occurred_at.isoformat(),"event_type":event.event_type,"source_ip":event.source_ip,
                "username":event.username,"outcome":event.outcome,"description":event.description}
            existing.add(fingerprint(values))
    new_rows=[item for item in parsed if item[1] not in existing]
    duplicates += len(parsed)-len(new_rows)
    return {"filename":name,"total_lines":len(lines),"valid_rows":len(parsed),"new_rows":new_rows,
        "duplicate_count":duplicates,"errors":errors}

def preview_upload(file_storage):
    parsed=parse_upload(file_storage)
    return {"filename":parsed["filename"],"total_lines":parsed["total_lines"],
        "valid_rows":parsed["valid_rows"],"would_import":len(parsed["new_rows"]),
        "duplicates":parsed["duplicate_count"],"malformed":len(parsed["errors"]),
        "errors":parsed["errors"][:100],"preview":[{k:v for k,v in row.items() if k not in {"metadata_json"}} for row,_ in parsed["new_rows"][:25]]}

def import_upload(file_storage, actor_id):
    parsed=parse_upload(file_storage)
    record=EventImport(import_id=str(uuid.uuid4()),filename=parsed["filename"],uploaded_by=actor_id,
        total_lines=parsed["total_lines"],imported_count=0,duplicate_count=parsed["duplicate_count"],malformed_count=len(parsed["errors"]))
    db.session.add(record);db.session.flush()
    imported=[]
    for payload,_key in parsed["new_rows"]:
        values=normalize_event(payload,simulated=False)
        event=SecurityEvent(**values,import_record_id=record.id)
        db.session.add(event);db.session.flush();evaluate_rules(event);imported.append(event)
        record.imported_count += 1
    audit("events.imported",record.import_id,actor_id,{"filename":record.filename,"imported":record.imported_count,
        "duplicates":record.duplicate_count,"malformed":record.malformed_count})
    db.session.commit()
    for event in imported:broadcast_event(event)
    return {"import_id":record.import_id,"filename":record.filename,"total_lines":record.total_lines,
        "imported":record.imported_count,"duplicates":record.duplicate_count,"malformed":record.malformed_count,
        "errors":parsed["errors"][:100]}
