# Kibana dashboard export

**ATT&CK Detection & Correlation — Windows-APT 2025**

[Open locally](http://localhost:5601/s/attack-correlator/app/dashboards#/view/attack-correlator-windows-apt-2025).
Sign in as `elastic` with the existing `ELASTIC_PASSWORD` in ignored `.env`.
First browser sign-in does not require a new account or password change.

`dashboard.ndjson` is exported from **live Kibana 9.5.3**, with three saved objects:
the 19-panel dashboard, referenced data view and the space's UTC/sample-size configuration.
Lens and Markdown panels are embedded. The export contains no credentials.

## Required data and import

The export contains no Elasticsearch data. Retain the verified source index
`windows-apt-events-*` and first run:

```powershell
.\.venv\Scripts\python.exe scripts/build_dashboard_data.py
```

This generates `attack-correlator-dashboard-v1`: 611 detection memberships,
261 ordered pairs (three refined), and nine scenario rows (three primary).

In a new Kibana space, open **Stack Management → Saved Objects → Import**, select
`kibana/dashboard.ndjson`, and allow overwrite of the empty space's default settings
object. Kibana initializes that object even in a new space. The validator confirms
the dashboard and data view are absent before import. Use a dedicated space: importing
this configuration into a populated space can replace its UTC/default-view settings.

The API equivalent is `POST /s/<space>/api/saved_objects/_import?overwrite=true`, using
multipart field `file` and `kbn-xsrf: true`. The helper authenticates inside the existing
container environment, outside host command arguments and reports.

Kibana can assign new global IDs when importing into another space. Follow returned
`destinationId` values and rewritten references. The import report records the actual
URL and IDs; do not assume the original IDs survive.

## Time and validation

The dashboard and each visualization retain **5 November–15 December 2024 UTC**.
The data view uses `@timestamp`, and exported settings specify `dateFormat:tz=UTC`.
The scope panel distinguishes fixed overview/scenario panels from the filterable evidence table;
Markdown evidence remains a generated snapshot.

```powershell
.\.venv\Scripts\python.exe scripts/build_dashboard.py
.\.venv\Scripts\python.exe scripts/validate_dashboard.py
# After recording real visual inspection for this export/import:
.\.venv\Scripts\python.exe scripts/validate_dashboard.py --reuse-import-check --require-visual
```

Validation compares every presentation document with source evidence, executes all
panel queries, checks daily/host buckets and references, imports into a clean space
and verifies the same results. The successful disposable space is retained for inspection.
Reports and real screenshots are under `analysis/dashboard/`. Rebuilding the export
requires a new import check and current visual evidence.

Counts are candidates/evidence units, not confirmed attacks. The 261 → 3 comparison is
not measured false-positive reduction. SCM service evidence stays separate from process
and user fields. No malicious/benign ground truth, severity, risk or confidence fields
are added. See [dashboard guide](../docs/dashboard.md) and [dashboard implementation](../docs/kibana-dashboard-implementation.md).
