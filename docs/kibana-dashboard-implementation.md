# Kibana dashboard build and validation

The [dashboard guide](dashboard.md) documents the 19 panels, fixed historical scope,
membership controls and source links. The implementation targets Kibana 9.5.3 and uses
its Dashboards API plus saved-object export/import. No scheduled Security rule is installed.

## Build from verified source data

Complete [detection prerequisites](individual-detection-implementation.md#reproduce)
after dataset preparation and ingestion. Then run from the project root:

```powershell
.\.venv\Scripts\python.exe scripts/check_stack.py
.\.venv\Scripts\python.exe scripts/build_scenario_evidence.py
.\.venv\Scripts\python.exe scripts/build_dashboard_data.py
.\.venv\Scripts\python.exe scripts/build_dashboard.py
.\.venv\Scripts\python.exe scripts/validate_dashboard.py
```

Use `.venv/bin/python` on Bash. The default scenario command replays detections and
correlation before preparing the bounded review. `--reuse-validated-prerequisites`
can avoid that replay only when saved hashes/counts still pass; it still checks live
source evidence. See [evaluation](evaluation.md).

The presentation builder verifies 1,096 required source IDs and creates 881
deterministic documents in `attack-correlator-dashboard-v1`: 611 event-within-rule
memberships, 261 ordered pairs with three refined flags, and nine scenario rows.
Strict ownership, mapping, count and complete-readback checks stop partial or drifting
builds. The source index receives no writes.

The dashboard builder creates the data view, UTC/sample-size settings and panels,
reads back the accepted definition and exports `kibana/dashboard.ndjson`. For an
existing export, follow the [import guide](../kibana/README.md).

## API, data, import and visual checks

The validator checks every presentation document, authored panel property, all six
metric expressions, exact daily/host buckets, source links and export references.
It imports into a clean space and follows remapped object IDs to verify equivalent
results. The successful space is retained for inspection; its URL is recorded in
`analysis/dashboard/import-validation.json`.

Browser inspection is a separate check. Review the overview, primary sequence,
supporting evidence, four membership counts and imported dashboard. A nonmatching
host query and shifted global time range should leave fixed overview/scenario panels
unchanged while the evidence table accepts its documented filters. Record actual
screenshots and the reviewed export in `analysis/dashboard/visual-inspection.json`.

After recording visual evidence for the current export/import, run:

```powershell
.\.venv\Scripts\python.exe scripts/validate_dashboard.py --reuse-import-check --require-visual
```

`--reuse-import-check` requires a matching successful import record; it is not a fresh
import test. `--require-visual` checks the saved visual record; it does not open a browser
or create screenshots. Rebuilding the export requires matching import and visual evidence.

Read the [report](../analysis/dashboard/dashboard-report.md),
[validation JSON](../analysis/dashboard/dashboard-validation.json),
[panel definition](../analysis/dashboard/dashboard-definition.json) and
[presentation manifest](../analysis/dashboard/presentation-manifest.json) together with
their recorded run times. Existing screenshots document their original inspection.

## Reporting

Counts are candidate observations and ordered tuples. The 261-to-3 reduction does not
measure false-positive reduction, and the primary SCM installation is separate from
the refined sc.exe cohorts. See [limitations](limitations.md). Report authoring and
archive output locations are documented in [release preparation](release-preparation.md).
