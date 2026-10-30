# Individual detection runbook

The historical runner executes ten ES|QL queries and three KQL review filters against
`windows-apt-events-*`. No scheduled Security rules are installed. The
[methodology](detection-methodology.md) explains the predicates and interpretation;
the [manifest](../detections/manifest.json) and three detection READMEs specify each query.

## Reproduce

Complete the README's dataset preparation, normalization and ingestion first. From
the project root, with the local stack healthy, run:

```powershell
.\.venv\Scripts\python.exe scripts/check_stack.py
.\.venv\Scripts\python.exe scripts/validate_ingestion.py --output-directory analysis/detections/prerequisites
.\.venv\Scripts\python.exe scripts/inspect_technique_candidates.py
.\.venv\Scripts\python.exe scripts/inspect_selection_relationships.py
.\.venv\Scripts\python.exe scripts/verify_technique_selection.py
.\.venv\Scripts\python.exe scripts/run_individual_detections.py
```

On Bash, use `.venv/bin/python`. The two inspection commands rebuild ignored process
and service projection caches and refresh selection provenance. They are required on
a fresh checkout/extraction or after re-ingestion. With unchanged, verified inputs,
existing caches can be reused; never bypass a mismatched hash.

The ingestion validator checks existing raw/processed integrity without regenerating
data. Its separate output directory preserves the original ingestion report whose
hash is checked by technique selection. If that original report is intentionally
regenerated, rebuild and verify selection before running downstream consumers.

Container restarts can replay Logstash's enabled input. Wait for ingestion to drain
and the stack to become healthy before validation; deterministic IDs prevent duplicate
inflation. No new ingestion or mapping change is needed for a detector-only replay.

## What the runner verifies

- Complete pre-limit counts, exact repeated query rows, searchable field capabilities,
  and distinct event/host sets; a 10,000-row export cap cannot silently truncate results.
- All 11,110 matching source IDs, fetched in batches of at most 1,000.
- Source predicates, returned flags, timestamps, and each refined set against its own
  baseline. ATT&CK annotations and scenario labels cannot drive predicates.
- Separate service installation, create-command, configuration-command and registry
  cohorts. They are not interchangeable event units.

The saved results contain 290 PowerShell, 172 shell, 41 service-create and 108
service-config refined events. See the [results](../analysis/detections/detection-results.json)
and [report](../analysis/detections/detection-report.md) for exact sets and recorded run time.
KQL files are broad review filters; ES|QL is authoritative for refinement.

The runner regenerates the manifest's validated counts, three detection READMEs and
result/report artifacts. Starting a run invalidates prior success output; resolve a
failure and rerun before treating those artifacts as validated.

## Verification and next steps

```powershell
.\.venv\Scripts\python.exe -m pytest -q --basetemp .test-tmp
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m pip check
```

Tests cover counting, missing fields, source/flag contradictions, bounded readback,
truncation, metadata independence and cohort separation. They do not measure detection
accuracy. Continue with [correlation](event-correlation-validation.md),
[evaluation](evaluation.md) and the [dashboard](kibana-dashboard-implementation.md).
