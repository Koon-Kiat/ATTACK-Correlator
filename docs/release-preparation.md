# Report authoring and release packaging

The engineering records in `docs/` and saved results in `analysis/` document
the project. Optional report sources and generated documents belong in the
Git-ignored `reports/` directory; they are not required to run the analytics.

## Report reproduction

`scripts/render_report_pdf.py` accepts a local `reports/technical-report.md` source and explicit
portrait/landscape page boundaries. It uses optional ReportLab, Pillow and pypdf
libraries with Windows Arial fonts; these are document-authoring dependencies, not
requirements of the analytics runtime. They were already available in the author's
document environment. From an environment containing those libraries, run:

```powershell
python scripts/render_report_pdf.py
python scripts/render_report_word.py
```

The PDF renderer fails if a declared page overflows. It records source/PDF hashes and figure provenance in the local render audit.
After every report edit, inspect the rendered PDF again and update the visual review
only after confirming the latest output. The selected figures are the dashboard
overview, the primary three-event scenario and the 41-row service-create evidence table.
Original PNGs remain under `analysis/dashboard/screenshots/`; clipping in the report
only removes unrelated viewport areas.

The Word renderer additionally uses optional `python-docx`. Run it after the PDF
renderer, which prepares the figure crops. The Word version keeps editable paragraphs
and tables. Pagination must be checked by rendering in Word or LibreOffice; check each generated document for clipping and overflow. These authoring dependencies are separate from the analytics environment.

Two historical PNG names were misleading: `02-primary-sequence.png` and
`03-supporting-evidence.png` depict negative filter tests. Their original bytes remain
for provenance, but `visual-inspection.json` explicitly excludes them as primary
scenario proof. `final-primary-scenario.png` supplies the correct primary capture.
Fresh `final-source-discover.png` and `final-detection-discover.png` support traceability.

## Verification and archive

The required live sequence is ingestion validation into the separate prerequisites
directory, technique-selection verification, the default scenario helper, presentation
data refresh and dashboard validation with the visual requirement. The default scenario
helper also runs the complete individual-detection and correlation validators. This
replays the existing analytics; it does not preprocess or re-ingest the source corpus.

```powershell
python scripts/validate_ingestion.py --output-directory analysis/detections/prerequisites
python scripts/verify_technique_selection.py
python scripts/build_scenario_evidence.py
python scripts/build_dashboard_data.py
python scripts/validate_dashboard.py --reuse-import-check --require-visual
python -m pytest -q --basetemp .test-tmp
python -m ruff check .
python -m ruff format --check .
python -m pip check
```

After reviewing and staging only intended project files, build the archive:

```powershell
python scripts/package_release.py
```

The packager reads Git-index blobs, preserving the byte hashes of historical artifacts.
It rejects unresolved merges, links, tracked generated reports, credentials, datasets,
private keys, caches and archives; `.env.example` is required. It checks archive CRCs
and reads back every member's SHA-256. `archive-validation.json` records the index tree
and every included filename, size and hash; `archive-contents.txt` lists all members.
Nothing under `reports/` is staged, included recursively or committed.

## Saved validation provenance

Saved validation JSON records the script hashes and results from its original run.
The wording cleanup changes comments or descriptions in `scripts/ingest.py`,
`scripts/build_dashboard.py` and `scripts/validate_dashboard.py`; those historical
hashes remain unchanged. Run the live validation commands above before treating
saved results as verification of the current script bytes.
