# SentinelSOC

SentinelSOC is an educational SOC and incident-response application. It records real authentication events emitted by its login flow, accepts authorized normalized events, imports a documented authentication CSV format, and evaluates database-backed detection rules. A controlled demo lab is clearly labeled and kept separate from observed events. This code is an educational portfolio project, not a production security appliance.

## Features

- Flask application factory, SQLite for local use/tests, PostgreSQL through psycopg for deployment, SQLAlchemy and Alembic migrations.
- Scrypt password hashing, login/logout, CSRF protection, generic login errors, timed sessions, rate limiting and role checks. No default account is created.
- Event normalization, UTC timestamps, deduplication by event ID, IP validation, source-token-authenticated ingestion and app-generated authentication records.
- Four configurable rules: source brute force, repeated failures against one account, password-spraying indicators, and success after repeated failures. Alerts include evidence and explanations; detections are not proof of compromise.
- Alert investigation and assignment; incident creation, assignment, notes, linked alerts, lifecycle, resolution, timeline, report and audit records.
- Admin user management, rule configuration, audit views, threat-intelligence lookup with optional OTX, analytics and formula-safe filtered CSV exports.
- Validated, previewable UTF-8 six-column authentication CSV imports with malformed-line summaries, deduplication and import provenance.
- Database-backed dashboard and Socket.IO live events with reconnect snapshot recovery; simulation events remain separately labeled.

The interface includes Overview, Live Events, Event Details, Alerts, Alert Details, Incidents, Incident Details, Threat Intel, Detection Rules, Audit Trail, Reports, User Management and Settings. Pages are backed by real records; optional external enrichment remains unknown/unavailable when no provider key is configured.

## Requirements

Python 3.11 or later. Tested here with Python 3.14. SQLite is bundled with Python. PostgreSQL is optional for local evaluation. Dependency versions are pinned in `requirements.txt`.

## Windows PowerShell: install and run locally

From the project directory:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
$env:SECRET_KEY = (python -c "import secrets; print(secrets.token_hex(32))")
$env:DATABASE_URL = "sqlite:///sentinelsoc.db"
$env:COOKIE_SECURE = "false"
flask --app wsgi db upgrade
flask --app wsgi init-db
flask --app wsgi create-admin
python devserver.py
```

The local URL is [http://127.0.0.1:5000](http://127.0.0.1:5000). `create-admin` prompts for the username and twice for a 12+ character password; it refuses to provision another administrator once one exists. Keep `SECRET_KEY` stable between restarts and set it through your secret manager or environment, never in source control. For a locally trusted LAN deployment, bind only behind a correctly configured reverse proxy and set `COOKIE_SECURE=true` when HTTPS is active.

`python devserver.py` binds to `127.0.0.1` and uses Flask-SocketIO's compatible local runner for WebSocket transport. For production, use a deployment stack that supports the selected Socket.IO transport (for example, a properly configured threaded Gunicorn setup with `simple-websocket`, TLS reverse proxy and message broker for multiple workers). Waitress can serve WSGI polling but does not upgrade WebSockets. Do not expose the development runner publicly.

For repeatable environments, copy `.env.example` to `.env`, replace the secret, and use Flask CLI (which loads dotenv when python-dotenv is installed). Do not commit `.env`.

## Database and migrations

SQLite is the default. `flask --app wsgi db upgrade` applies committed migrations; `flask --app wsgi init-db` safely creates missing local tables and inserts the initial rule configuration. For PostgreSQL, create a database and set a URL such as:

```powershell
$env:DATABASE_URL = "postgresql+psycopg://sentinel_app:YOUR_PASSWORD@127.0.0.1:5432/sentinelsoc"
flask --app wsgi db upgrade
```

Use a restricted PostgreSQL role and external secret storage. To author a later migration after a model change: `flask --app wsgi db migrate -m "describe change"`, review the generated script, then apply with `flask --app wsgi db upgrade`.

## Administrator and analyst accounts

Provision the first administrator with `flask --app wsgi create-admin`; it securely prompts for a password and refuses when an administrator already exists. Administrators can create users, reset passwords, set roles, and disable users. Analysts cannot manage users or change detection configuration.

## Controlled brute-force demonstration

1. Sign in as the administrator or analyst.
2. Open **Overview → Controlled demo lab** and choose **Repeated failures · brute force**.
3. Generate events. Five labeled simulated authentication failures from localhost are persisted; the configured rule generates a high alert.
4. Open the alert, acknowledge it, and select **Create incident**. Add an investigation note and resolve the incident.
5. Review **Live Events**, **Alerts**, **Incidents**, and **Audit Trail**. The event and alert records carry a simulation flag; simulated records are excluded from observed-event detection windows.

The API also accepts one normalized JSON event per authenticated session at `POST /api/events` (CSRF header required), or a source-token-authenticated event at `POST /api/ingest` using `X-Ingest-Token`. The latter is disabled until configured. Request bodies are limited to 1 MB. CSV import supports headerless UTF-8 rows in this exact order: `timestamp,event_type,source_ip,username,outcome,description`; extension, byte/row caps, parser validation and preview are enforced.

## API summary

All routes except health, login and token-protected ingestion require an authenticated session. Mutating session routes require a CSRF token (`X-CSRFToken` for JSON). Responses use JSON; record lists are capped to 200 entries.

| Route | Purpose |
| --- | --- |
| `GET /api/dashboard` | Database-derived counters, recent events and alerts |
| `GET /api/analytics?days=7` | Database-derived trends, rule counts and incident statistics |
| `GET /api/events?outcome=failure&simulated=false&limit=50&offset=0` | Filtered, ordered event page |
| `POST /api/events` | Authenticated normalized event ingest |
| `GET /api/alerts`, `GET /api/incidents`, `GET /api/rules`, `GET /api/audit` | Lists for current operator |
| `POST /api/alert/<id>/status` | Acknowledge/update alert |
| `POST /api/alert/<id>/incident` | Convert an alert to an incident |
| `POST /api/incident/<id>/update` | Set incident status and add note/resolution text |
| `POST /api/incident/<id>/assign`, `POST /api/incident/<id>/alerts` | Assign and link incident work |
| `POST /api/imports/preview`, `POST /api/imports` | Preview and import supported authentication CSV |
| `GET /api/export/events.csv`, `/api/export/alerts.csv` | Filtered, formula-safe CSV exports |
| `GET /api/export/incident/<uuid>.html` | Investigation report and event timeline |
| `GET /api/threat-intel?ip=<address>` | Optional rate-limited OTX enrichment |
| `POST /api/demo` | Run one bounded, fixed localhost scenario |
| `POST /api/ingest` | Shared-token event ingest (`INGEST_TOKEN`) |
| `GET /api/health` | Public minimal database/app health |

Socket.IO namespace `/live` requires an authenticated session. Dashboard reconnects and refreshes its snapshot periodically to recover missed broadcasts. This is not a durable message queue; high availability requires an external broker and worker design.

## Testing

```powershell
python -m pytest -q
```

Tests use isolated SQLite databases. They cover login/password hashing, CSRF, authorization, ingestion and imports, detection thresholds/windows/out-of-order events, incident lifecycle and user administration, audit, formula-safe exports, threat-provider responses and caching, retention, and Socket.IO authentication/reconnect recovery. They do not establish production readiness or distributed concurrency guarantees.

## Security checklist and limitations

- Generate and protect `SECRET_KEY`; configure `COOKIE_SECURE=true` behind HTTPS; use a dedicated PostgreSQL role and restricted network access.
- Set a long random `INGEST_TOKEN`; limit it at the reverse proxy, rotate it, and never send it over plaintext remote connections.
- Configure a shared rate-limit backend for multi-process deployment. Current Flask-Limiter uses in-memory storage by default; set `RATELIMIT_STORAGE_URI=redis://127.0.0.1:6379/0` and operate a protected Redis service for shared rate limits.
- Keep event retention bounded. `flask --app wsgi retain-events --days 90` is a dry run; `--apply` performs audited deletion while preserving alert evidence. Schedule only after your retention policy and backups are approved.
- Audit rows are application-level records in the same database; a database administrator can alter them. Send audit records to an external append-only system for tamper resistance.
- OTX enrichment calls AlienVault's documented indicator API only when `OTX_API_KEY` is configured; responses are cached and provider failures remain unavailable/unknown. Provider results are not proof that an address is benign or malicious. See [OTX API documentation](https://otx.alienvault.com/api/).
- The rolling detection correlation is transaction-backed, but multi-worker PostgreSQL race behavior has not been stress-tested; deploy with a serialized task/broker design before high volume.
- The detector is a straightforward rule, not AI. The threshold is evidence of suspicious activity only. It must not automatically block or scan IPs.
- Login limiter source state defaults in memory. Failed login rows are recorded as audit records and auth events, but persistent account lockout and shared distributed controls are not implemented.
- The demo uses a fixed loopback address and reports all records as simulated. Simulation is not an emulation of an attacker and sends no traffic beyond this application.
- Review pinned dependencies routinely (`python -m pip list --outdated`, `pip-audit` in a separate approved environment, and upstream advisories). Review lock changes and run tests before deployment.

## Troubleshooting

- **SECRET_KEY error:** set `$env:SECRET_KEY` before invoking Flask; do not use the example placeholder.
- **No administrator:** run `flask --app wsgi create-admin` from the activated environment.
- **Missing tables:** run `flask --app wsgi db upgrade`, then `flask --app wsgi init-db`.
- **PostgreSQL driver error:** confirm `DATABASE_URL` uses `postgresql+psycopg://` and dependencies installed from this requirements file.
- **No live connection:** verify authenticated session and Socket.IO endpoint access. Snapshot refresh runs every 30 seconds; check browser console and proxy settings.
- **No alert:** verify five or more observed failures share an IP in the configured time window; simulated and observed event windows are separate; check rule is enabled.
- **CSV begins with apostrophes on some cells:** formula-leading values are intentionally escaped for spreadsheet safety.

## License

MIT. See [LICENSE](LICENSE).
