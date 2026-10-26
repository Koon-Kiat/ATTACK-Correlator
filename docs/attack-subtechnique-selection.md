# ATT&CK sub-technique selection

This engineering record preserves the observations and checks for this workflow.
For the completed implementation and current status, see the [project README](../README.md).

Date: 13 September 2026, Singapore. Scope: final sub-technique selection and detection
planning from the completed dataset inspection through ingestion validation evidence and live Elasticsearch. No raw/processed
data, preprocessing or ingestion configuration was changed. No final detection or
correlation queries, installed Security rules or dashboard were created.

## Completed work and methodology

Read-only ingestion validation validation passed, including the existing full data normalization conservation
and hash checks. The live index remains **102,011 events: 90,601 timed, 11,410 undated**.
Historical event time was preserved. Review used the dataset inspection candidate inventory,
29 provider/behaviour-based live queries, representative source readbacks and official
ATT&CK/CAR references accessed on 12 September 2026 UTC.

| Selected sub-technique | Why selected | Observable evidence; time coverage |
|---|---|---|
| T1059.001 PowerShell | Direct argument/ancestry evidence, independent descendants and administrative comparison opportunities | 2,060 Sysmon 1 launches; 1,726 broad encoded-or-bypass matches; all timed |
| T1059.003 Windows Command Shell | Distinct interpreter/argument contract, service-parent examples and GUID-linked children | 7,717 Sysmon 1 launches, including three service-origin shells; all timed |
| T1543.003 Windows Service | Direct installation observations plus service-control/registry evidence and update comparisons | 102 SCM 7045 installations; separate 155 create, 117 binPath-config and 708 ImagePath-write events; all timed |

All selected IDs are actual sub-techniques. Sharing T1059 is justified by distinct
interpreter behaviour and independent process records; Service adds another mechanism,
two tactics and another provider. Source annotations and derived scenarios remain
context, never selection proof, query predicates or join keys.

The [selection document](../analysis/technique_selection.md) includes candidate ratings,
contracts, ten detailed representative examples, source rows, rejected alternatives,
ATT&CK log-source and CAR tables, correlation keys, window comparisons, FP/FN
concerns and dashboard implications. The adjacent JSON retains exact structured evidence.

## Strongest evidence and implementation direction

Three observed SCM installation → services-origin cmd.exe → PowerShell relationships
combine installation-object and GUID evidence. The DESKTOP-FMI6MML example has three
distinct events, two explicit UTC gaps of 21,537,200 and 13,282,500 ns, and a total
0.0348197-second span. Full commands connect installation to shell; the shell's actor
GUID connects to PowerShell's parent GUID. This is stronger corroboration of execution
than an isolated process name, but authorized marker-file tests remain plausible.

The broader process review finds 120 PowerShell→shell, 261 shell→PowerShell and 268
shell→service-control ordered pairs, unchanged at 60/300/900 seconds. These are
exploratory pairs, not installed-rule alerts. The current ECS mapping can support the
two-event service-origin shell→PowerShell pair. SCM serviceName/imagePath are unindexed
original evidence; automating the third object match requires a reviewed extraction
decision later. technique selection did not modify mappings to bypass that constraint.

The completed [individual detection implementation](individual-detection-implementation.md)
validates these three baseline/behavioral contracts, historical matches and missing-field
behavior. Standalone candidates remain alongside stronger variants; the separate
[event correlation record](event-correlation-validation.md) documents the implemented joins.

## Rejected alternatives and unresolved limitations

Scheduled Task has 59 creation commands but lacks native task-registration and task-file
corroboration. UAC has suggestive registry/utility activity without a verified elevation
outcome. File Deletion lacks convincing observed anti-forensic deletion; generic DLL
loads do not establish hijacking. Compiler launches lack delivery/resulting-executable
confirmation, and WinRM ports lack corresponding wsmprovhost child-process evidence.
Their official guidance is recorded; the stronger selected relationships drive ranking.

Native PowerShell logs and several recommended Security feeds are absent. Some parent
records/GUIDs are missing. The 11,410 undated events cannot enter ordered correlation.
Service-object search remains limited. Routine command semantics and update-looking
paths are comparison candidates, not independently verified benign events. No binary
event-level truth supports precision, recall, F1 or FPR. Correlation may miss delayed,
unlogged or single-event activity; lower alert volume does not prove better accuracy.

## Files created or updated

| Area | Files |
|---|---|
| Required selection outputs | `analysis/technique_selection.md`, `analysis/technique_selection.json`, `docs/attack-subtechnique-selection.md` |
| Reproducible evidence | `analysis/selection/exploratory-queries.json`, `correlation-feasibility.json`, `live-state.json`, `selection-verification.json` |
| Retained read-only helpers | `scripts/inspect_technique_candidates.py`, `inspect_selection_relationships.py`, `verify_technique_selection.py` |
| Automated verification | `tests/test_technique_selection.py` |
| Consistent project guidance | `README.md`, `docs/detection-methodology.md`, `docs/correlation.md`, `docs/evaluation.md`, `docs/limitations.md` |
| Existing validation report refreshed | `analysis/ingestion/ingestion-validation.json` by the read-only ingestion validation validator |

Projected process/service evidence caches under ignored `analysis/inspection/` are
regenerable. Current V4 raw evidence remains intact; cleanup history is in environment setup and
dataset notes. No full dataset or credentials are added to Git.

## Tests and verification

- `python scripts/validate_ingestion.py`: passed existing full data normalization verification and
  live ingestion validation checks, including exact counts and timestamp preservation.
- `python scripts/verify_technique_selection.py`: **passed**; replayed **29 queries**,
  compared **141 retained projections across 114 unique event IDs** against live
  Elasticsearch, and recomputed relationships from **20,814 fresh process records and
  102 installation records**. All three object/GUID chains reproduced.
- `python -m pytest -q --basetemp .test-tmp/workflow-check`: **101 passed**. Twelve new
  tests cover nanosecond boundaries, missing/reversed times, host/GUID joins, duplicate
  document versus identity behaviour, full-command object matching, metadata independence,
  incomplete counts/readbacks, evidence comparison and selection/count guards.
- `python -m ruff check .`: passed; `python -m ruff format --check .`: 33 files formatted.
- `python -m pip check`: no broken requirements.

All helpers make read-only Elasticsearch requests. Tests use benign synthetic software
fixtures; no dataset command was executed and no attack traffic was generated.
