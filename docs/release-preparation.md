# Report authoring and release packaging

The [documentation guide](README.md) covers maintained instructions; saved evidence
under `analysis/` retains its recorded validation scope and hashes. Optional report
sources and generated documents belong in Git-ignored `reports/`. They are not required
to run the analytics and are not included in the code archive.

## Report reproduction

Supply the reviewed source at `reports/technical-report.md`. A plain Git checkout and
the generated code ZIP do not include that source. Do not recreate unavailable originals.
The PDF renderer uses optional ReportLab, Pillow and pypdf; the Word renderer also
requires python-docx. Use an authoring environment on Windows with Arial fonts, separate
from the analytics environment. From the project root, run:

```powershell
python scripts/render_report_pdf.py
python scripts/render_report_word.py
```

The PDF renderer uses explicit portrait/landscape page boundaries and fails on page
overflow. Its `--source` and `--output` options override the defaults. Default PDF/Word
outputs remain under `reports/`. The PDF step prepares figure crops used by the Word
renderer. Inspect both rendered documents after edits for pagination, clipping and
overflow; source parsing alone is not visual verification.

Render audits record source/output hashes and figure provenance. Original screenshots
remain under `analysis/dashboard/screenshots/`. The historical `02-primary-sequence.png`
and `03-supporting-evidence.png` capture negative filter tests; they are excluded as
primary-scenario proof in `visual-inspection.json`. Use `final-primary-scenario.png`
for the primary scenario and retain source/Discover captures for traceability.

## Validate the analytics before release

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
.\.venv\Scripts\python.exe -m pytest -q --basetemp .test-tmp
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m pip check
```

The scenario helper includes full detection/correlation replay. The two selection
inspection commands rebuild ignored caches for a fresh checkout or extraction.
If the dashboard has not been built, or its definition changed, run
`scripts/build_dashboard.py` after building presentation data and before validation.
See the [dashboard runbook](kibana-dashboard-implementation.md).

After reviewing the current dashboard in a browser and recording matching visual
evidence, run `scripts/validate_dashboard.py --reuse-import-check --require-visual`.
This checks saved import/visual records; it does not perform a browser inspection.
Keep historical checks and fresh checks distinguishable.

## Build and verify the archive

Review and stage the exact project changes intended for the release. The current
packager reads **Git-index blobs**, including reviewed staged changes; it does not
read unstaged edits or untracked files. Check `git diff --cached` before packaging:

```powershell
.\.venv\Scripts\python.exe scripts/package_release.py
```

The default output is `reports/ATTACK-Correlator-code.zip`. `--output` must point inside
the ignored `reports/` directory. The command requires a Git checkout, so it cannot
rebuild directly from an extracted code ZIP without a reviewed Git index.

The packager rejects forbidden staged paths, local credential values and private-key
markers. It verifies archive CRCs and every member's SHA-256. Adjacent
`archive-validation.json` records the Git index tree, blob IDs and member hashes;
`archive-contents.txt` lists members. It does not validate Markdown links, bundle the
editable report, or include rendered PDF/Word files. Deliver report artifacts separately.

Independently inspect and test the extracted package. Obtain the dataset separately
and rebuild ignored caches rather than copying development state. Old archive counts
and checks do not validate a new ZIP. Never distribute development archives containing
local configuration or source datasets.

## Saved validation provenance

Validation JSON records implementation hashes and results from its original run.
Source edits can invalidate those hashes even when only comments changed. Preserve
old evidence and run affected validators before claiming current implementation
verification. Documentation review and successful packaging do not prove live query
execution, browser behavior or report layout.
