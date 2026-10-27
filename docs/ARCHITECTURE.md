# Architecture and implementation boundaries

`sentinelsoc/__init__.py` builds the app and initializes extensions. `models.py` defines users, normalized events, imports, rules, alerts, incidents, notes, audit records and threat cache. `auth.py` handles sessions and role guards; `services.py` normalizes/persists events, audits and evaluates detections; `log_imports.py` previews and imports the supported CSV format; `threat_intel.py` handles optional OTX lookups/cache; `analytics.py` queries reporting aggregates. `api.py` owns JSON reads/ingest and `routes.py` owns HTML views and state transitions. Templates/assets are under `templates/` and `static/`; migrations and integration/security tests are under their respective directories.

## Data flow

Application login → audit record + normalized authentication event → transaction → rule evaluation and evidence alert → per-active-user Socket.IO broadcast → client cursor recovery. Authorized session ingestion requires CSRF; optional source ingestion uses the configured shared token. CSV uploads stay in memory, are limited by request/row/size controls, preview up to a bounded set of valid rows, and persist import provenance when committed. No uploaded file is stored or executed.

## Database

Tables: `user`, `security_event`, `event_import`, `detection_rule`, `alert`, `incident`, `incident_alert`, `investigation_note`, `audit_record`, `threat_intel_cache`. Events index event ID, time, type, outcome, IP, username and simulation marker; import-linked events preserve provenance. Alert `episode_key` is unique; alert evidence stores event identifiers. SQLite is suitable for local evaluation/tests. PostgreSQL is the deployment target, but high-concurrency detection has not been stress-tested and should be serialized through a worker/queue before high-volume multi-worker operation.

## Detection and ATT&CK

Shipped rules include same-source brute force, repeated account failures across sources, password-spraying indicators across accounts, and successful authentication after repeated failures. All use bounded rolling event-time windows, isolate simulated/observed evidence, and explain rule reasoning. The rules identify suspicious patterns, not compromise or actor attribution. See `DETECTIONS.md` for tuning and ATT&CK limitations.

## Providers and reports

Optional enrichment uses the AlienVault OTX indicator general endpoint through a provider abstraction, with bounded timeout/response, rate-limit handling, cache expiry and explicit positive/negative/unknown/unavailable states. No lookup occurs without `OTX_API_KEY`. Analytics and exports are derived from database records; incident HTML reports contain a timeline, related alerts/events, notes and resolution. CSV formula prefixes are escaped.

## Deployment model

Local live transport runs through `python devserver.py`, which calls `socketio.run` on loopback. For deployment, use a maintained Socket.IO-capable server, TLS, secure cookies, secret storage, restricted PostgreSQL account, shared rate-limit backend, request limits and centralized logs. Waitress serves polling-compatible WSGI but not WebSocket upgrades; multiple workers also require a message broker. This project has not been independently penetration-tested.
