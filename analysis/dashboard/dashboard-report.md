# Live dashboard validation

**ATT&CK Detection & Correlation — Windows-APT 2025** · Kibana 9.5.3 · UTC

Validated: 2026-09-16T12:50:46.267416+00:00. API/data/import checks: **passed**. Visual inspection: **passed**.

| Analytical unit | Live result |
|---|---:|
| Detection event-within-rule memberships | 611 |
| PowerShell / shell / service-create / service-config distinct events | 290 / 172 / 41 / 108 |
| Broad / refined ordered pairs | 261 / 3 |
| Refined participating events / hosts | 6 / 3 |
| Ordered triples / scenario rows / primary rows | 3 / 9 / 3 |
| Presentation documents | 881 |

Every generated document equals its live indexed counterpart; 1096 required source IDs were fetched and verified. Source totals remain 102,011 / 90,601 timed / 11,410 undated; the mapping hash is unchanged. Both chart series reconcile by exact day and host, not only grand total. All six metric aggregation filters were executed using their live KQL expressions.

The 19 live panels retain a fixed **5 November–15 December 2024 UTC** scope. The native Detection Event Evidence table reproduces all four membership row sets (290/172/41/108), with exact individual detection ID equality and one original source record per ID. The primary DESKTOP-DS4FBF4 sequence retains exact source IDs, UTC nanoseconds, the GUID edge, source-only SCM image evidence and its **41,801,900 ns** span. Commands remain inert text; missing fields display as Unavailable.

`kibana/dashboard.ndjson` was exported from live Kibana with the data view and UTC settings: 3 objects, 0 missing references. A clean space `attack-correlator-check-e51876158514` accepted all objects, resolved every panel and reproduced the exact live query results. This disposable validation space is retained for inspection.

261 → 3 is candidate sequence volume reduction, **not measured false-positive reduction**. No independent malicious-intent or execution-outcome truth exists. Strict ancestry, source evidence and timing can miss alternate execution paths or incomplete telemetry. The SCM installation observation remains distinct from refined sc.exe create/config cohorts. This is a presentation layer, not a new detector.

Reproduce: `python scripts/build_dashboard_data.py`, `python scripts/build_dashboard.py`, `python scripts/validate_dashboard.py`. After real browser inspection, use `python scripts/validate_dashboard.py --reuse-import-check --require-visual`. Detailed queries, buckets, source/mapping hashes and screenshot evidence are in `dashboard-validation.json`.
