# Detection rules

Rules are enabled and configured in the database. Administrators may enable/disable supported rules and update integer threshold/window values. Changes are validated and audited; ingestion reads current settings for each evaluation. Observed and simulated data are always evaluated separately.

| Rule | Default | Detection | ATT&CK context |
| --- | --- | --- | --- |
| `auth.bruteforce` | 5 / 60s | Failed authentications from one IP in a rolling window | T1110 Brute Force, broad contextual mapping |
| `auth.account_failures` | 5 / 60s | Failed authentications against one account across sources | T1110 Brute Force, broad contextual mapping |
| `auth.password_spray` | 5 / 60s | One source fails against at least threshold distinct accounts | T1110.003 Password Spraying, indicator only |
| `auth.success_after_failures` | 3 / 300s | A successful auth after repeated failures for the same account | No direct technique mapping; pattern alone is inconclusive |

All alerts include a rule explanation, threshold, observed count and supporting event identifiers. Brute-force thresholds are constrained to 2–100 and windows to 10–3600 seconds. Other rules use the same supported bounds. Timestamps are normalized to UTC; event-time out-of-order arrivals are considered within the bounded query window. Episode uniqueness and a recent-correlation check suppress duplicates; SQLite is not a distributed concurrency test environment, and high-volume multi-worker deployment should serialize detection through a queue.

ATT&CK mapping is contextual and does not establish adversary behavior. MITRE describes T1110 as brute force and T1110.003 as password spraying; this detector observes authentication patterns only. Sources: [T1110](https://attack.mitre.org/techniques/T1110/) and [T1110.003](https://attack.mitre.org/techniques/T1110/003/).

Alerts do not prove compromise. Review source diversity, service context, MFA, known user behavior and adjacent telemetry. SentinelSOC does not block, attack, or scan external systems.
