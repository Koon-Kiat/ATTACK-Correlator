# Revalidating the analytics

The [documentation guide](README.md) covers maintained instructions; saved evidence
under `analysis/` retains its recorded validation scope and hashes. Run these checks
after changing the pipeline and before claiming current results. CI cannot run them
because they need the dataset and a live Elastic stack.

## Commands

Complete dataset preparation, preprocessing and ingestion from the project README.
With the local stack healthy, use the analytics environment:

```powershell
.\.venv\Scripts\python.exe scripts/validate_ingestion.py --output-directory analysis/detections/prerequisites
.\.venv\Scripts\python.exe scripts/inspect_technique_candidates.py
.\.venv\Scripts\python.exe scripts/inspect_selection_relationships.py
.\.venv\Scripts\python.exe scripts/verify_technique_selection.py
.\.venv\Scripts\python.exe scripts/build_scenario_evidence.py
.\.venv\Scripts\python.exe scripts/build_dashboard_data.py
.\.venv\Scripts\python.exe scripts/validate_dashboard.py
.\.venv\Scripts\python.exe scripts/verify_evidence.py
.\.venv\Scripts\python.exe -m pytest -q --basetemp .test-tmp
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m pip check
```

The scenario helper includes full detection/correlation replay. The two selection
inspection commands rebuild ignored caches for a fresh checkout. If the dashboard has
not been built, or its definition changed, run `scripts/build_dashboard.py` after
building presentation data and before validation. See the
[dashboard runbook](kibana-dashboard-implementation.md).

After reviewing the current dashboard in a browser and recording matching visual
evidence, run `scripts/validate_dashboard.py --reuse-import-check --require-visual`.
This checks saved import/visual records; it does not perform a browser inspection.
Keep historical checks and fresh checks distinguishable.

## Saved validation provenance

Validation JSON records implementation hashes and results from its original run.
Source edits can invalidate those hashes even when only comments changed. Preserve
old evidence and run the affected validators before claiming current implementation
verification. A documentation review does not prove live query execution or browser
behavior.

Original screenshots remain under `analysis/dashboard/screenshots/`. The historical
`02-primary-sequence.png` and `03-supporting-evidence.png` capture negative filter
tests; they are excluded as primary-scenario proof in `visual-inspection.json`. Use
`final-primary-scenario.png` for the primary scenario and retain source/Discover
captures for traceability.
