# Security and deployment guidance

- Keep secrets outside source control. Replace development keys and enable secure cookies on HTTPS.
- Enforce TLS, proxy request limits, trusted-host handling, least-privilege DB credentials, network ACLs, backups and monitoring at deployment.
- Set a random ingestion token only when required; use a dedicated credential, rotation process, HTTPS, and source network controls.
- Use centralized rate limiting for multiple processes and test login abuse controls under deployment topology.
- Review dependency advisories and run an approved scanner against pinned dependencies before releases. Pin changes deliberately; do not auto-upgrade in production.
- Audit table is append-oriented through the UI but not tamper-proof against host/database administrators.
- Threat intelligence is optional and rate-limited. A positive result means the provider reported pulse matches, not malicious certainty; negative is not benign certainty. Without credentials or on provider failures, the status is unavailable/unknown.
- Supported CSV imports are constrained and safe-parsed, but imported authentication records remain user-supplied evidence. Validate source provenance before relying on them for decisions.
- Event retention is a dry-run-first CLI operation. Alert-referenced evidence is retained, but incident reports may refer to non-alert events that have expired; back up and coordinate retention policy accordingly.
- Socket.IO checks session authentication and active-user status. Multi-worker broadcasting requires a broker and deployment testing.
- No automatic containment or external probing is implemented.
- This educational implementation has not undergone independent penetration testing and must not be represented as production-ready or vulnerability-free.
