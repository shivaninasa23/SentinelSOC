# API and event format

## Normalized event

```json
{
  "event_id": "optional UUID; generated if omitted",
  "occurred_at": "2026-10-27T12:30:00Z",
  "event_type": "authentication",
  "source_system": "sentinelsoc-auth",
  "source_ip": "127.0.0.1",
  "username": "analyst",
  "outcome": "failure",
  "severity": "low",
  "description": "Application login failed",
  "metadata": {},
  "correlation_id": "optional",
  "simulated": false
}
```

`event_type`, `source_system`, and `description` are required. Outcomes are `success`, `failure`, or omitted. Severity is critical/high/medium/low. IP is validated with Python's IP parser. Supplied timestamps must be ISO-8601 with timezone and cannot exceed server time by more than five minutes. Metadata must be an object. Server-controlled app and demo code set simulation state; client payloads cannot force a record into the simulated partition.

## CSV authentication line

The import interface accepts headerless UTF-8 or UTF-8-BOM CSV with columns: `timestamp,event_type,source_ip,username,outcome,description`. Only `authentication` and `success`/`failure` records are supported. Uploads must use `.csv`, are limited to 1 MB and 10,000 lines, stay in memory, and are parsed as data only. Preview endpoints return bounded valid examples and malformed-line diagnostics. Import endpoints create an `event_import` provenance record and link persisted rows. Duplicates inside a file and against retained imports are counted and skipped.

## Routes

All API routes require an authenticated session except minimal health and token-authenticated `POST /api/ingest`. Session mutations require CSRF. See the README route table for dashboard, events, alerts, incidents, analytics, imports, threat lookup, exports, and rule management. Event/alert/incident list endpoints paginate. Session ingestion uses `X-CSRFToken`; source ingestion compares `X-Ingest-Token` in constant time and is disabled unless `INGEST_TOKEN` is configured. Use HTTPS and network restrictions for non-local use.
