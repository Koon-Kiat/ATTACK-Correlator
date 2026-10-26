# Kibana dashboard implementation

This engineering record preserves the observations and checks for this workflow.
For the completed implementation and current status, see the [project README](../README.md).

**ATT&CK Detection & Correlation — Windows-APT 2025** presents the unchanged individual detection through scenario evaluation
analytics on live Kibana **9.5.3**. Source data retains **102,011 observations / 90,601
timed / 11,410 undated** and its original mapping.

## Implementation and units

`scripts/build_dashboard_data.py` verifies prerequisite hashes, live memberships, all
broad pair structures, source projections and all three triples. It checks 1,096 required
source IDs and creates 881 deterministic documents in `attack-correlator-dashboard-v1`.
Strict mapping ownership, count guards and complete readback protect repeat runs.

| Evidence | Validated result |
|---|---|
| PowerShell / shell / service-create / service-config | 290 / 172 / 41 / 108 distinct events within each rule |
| Activity | 611 event-within-rule memberships |
| Broad / refined correlation | 261 / 3 ordered pairs; refined six participating events / three hosts |
| Service corroboration | Three ordered triples / nine scenario rows / three primary rows |
| Presentation index | 881 documents |

`scripts/build_dashboard.py` creates the data view, UTC settings and 19 live panels through
the supported Dashboards API, reads them back and exports `kibana/dashboard.ndjson`.
Eight Lens panels provide six metrics and daily/host stacked activity. Nine Markdown
panels provide scope, candidate comparison, primary relationship, three ordered evidence
cards, supporting table, traceability guidance and interpretation. A native Discover
document table and single membership selector expose all 611 detection memberships.
Service-create and service-config stay separate.

The primary DESKTOP-DS4FBF4 sequence preserves all three IDs, nanosecond timestamps, its
**41,801,900 ns** span, exact GUID ancestry and independently validated SCM image association.
Missing fields display as **Unavailable**; commands remain inert. SCM 7045 is an installation
baseline, outside the refined sc.exe process cohorts. No source dataset, ingestion mapping,
detection predicate, correlation algorithm or scenario selection changed.

All panels retain **5 November–15 December 2024 UTC**. The header distinguishes fixed
overview/scenario panels from the filterable detection table. Kibana's ignore-global-filters
option also ignores panel queries, so metric cohort predicates live inside the metric
aggregation. A regression test and real browser check cover that behavior.

Evidence filters return exactly 290/172/41/108 document rows, with complete individual detection
ID equality and original-event resolution. Source-ID links open `windows-apt-events-*`
in Discover; explicit rule links preserve historical membership.
They do not rely on Lens's aggregated View data. The native Open in Discover action can
drop control state, so the explicit links carry rule predicates and UTC bounds themselves.

## Reproduction and verification

```powershell
.\.venv\Scripts\python.exe scripts/check_stack.py
.\.venv\Scripts\python.exe scripts/build_scenario_evidence.py --reuse-validated-prerequisites
.\.venv\Scripts\python.exe scripts/build_dashboard_data.py
.\.venv\Scripts\python.exe scripts/build_dashboard.py
.\.venv\Scripts\python.exe scripts/validate_dashboard.py
.\.venv\Scripts\python.exe -m pytest -q --basetemp .test-tmp/dashboard
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m pip check
```

The scenario evaluation reuse mode still checks hashes and live evidence; its default mode also
replays individual detection and event correlation. `scripts/validate_dashboard.py` checks every generated document,
every authored live panel property, all six metric expressions, exact daily/host buckets,
export references and a clean-space import. `scripts/kibana_local.py` keeps credentials
inside the existing container environment, outside host arguments and reports.

The export contains dashboard, data view and UTC settings. Import follows remapped IDs
and verifies the same results. Only the new space's automatically initialized settings
object needs overwrite. The successful validation space is retained for inspection;
earlier disposable attempts are removed. The actual URL is in `import-validation.json`.

Real browser inspection covers overview, primary sequence, supporting evidence and the
imported dashboard. A nonmatching host query and shifted global time window verify fixed
totals. `visual-inspection.json` binds the reviewed export to actual screenshots and checks.
Final validation uses:

```powershell
.\.venv\Scripts\python.exe scripts/validate_dashboard.py --reuse-import-check --require-visual
```

The full suite passes **241 tests**, including 28 new dashboard tests. See the
[validation report](../analysis/dashboard/dashboard-report.md),
[machine-readable results](../analysis/dashboard/dashboard-validation.json),
[panel definition](../analysis/dashboard/dashboard-definition.json),
[presentation manifest](../analysis/dashboard/presentation-manifest.json),
[screenshots](../analysis/dashboard/screenshots/) and [import guide](../kibana/README.md).

## Interpretation and reporting

261 → 3 is **candidate sequence volume reduction**, not measured false-positive reduction.
Approved administration and tests can match; missing logs/GUIDs, alternate interpreters
and delays can evade strict correlation. Intent and execution outcome remain unproven.
No independent truth supports accuracy, severity or confidence charts. This bounded
scenario is not a full incident reconstruction.

Technical reports can use the retained screenshots, captions and references.
Generated documents and code archives remain local under the ignored `reports/` directory.
