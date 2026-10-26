# Dataset inspection and evidence inventory

This engineering record preserves the observations and checks for this workflow.
For the completed implementation and current status, see the [project README](../README.md).

Scope: read-only inspection of the supplied Windows-APT 2025 v4 extract. Final review:
2026-09-12. This historical checkpoint preceded preprocessing, ingestion and technique selection; their completed records are linked in the README.

## Completed work

The inspector inventories all 28 raw files, completely profiles 20 CSVs and one
notebook JSON document, and retains exact field spellings, types, examples, missing/null
counts, distinct-value limits, timestamp formats, duplicates and parse diagnostics.
The evidence inventory distinguishes actual Wazuh event annotations from ATT&CK IDs
mentioned in manifests, SCA assessments, publisher code, documentation and event text.

It verifies the source-row scenario join, compares combined and period representations,
rates all 21 event-labelled sub-techniques, and explores distinct-event relationships
using explicit Windows UTC time. Correlation examples preserve source filenames, row
indices, document IDs, labels, attribution strength, telemetry and time gaps. Conditional
ECS proposals use only observed fields. All statistics in the analysis artifacts are
generated from source bytes; this document summarizes those generated findings.

## Files created or modified

| Area | Files |
|---|---|
| Extended inspector | `src/preprocessing/inspect_dataset.py` |
| Added inspection modules | `profile_values.py`, `windows_fields.py`, `event_inventory.py`, `correlation_inventory.py`, `evidence_inventory.py`, `inventory_reports.py` under `src/preprocessing/` |
| Generated required outputs | [dataset inventory](../analysis/dataset_inventory.md), [ATT&CK coverage](../analysis/attack_coverage.md), [schema JSON](../analysis/dataset_schema.json), [ECS proposals](../analysis/ecs_mapping_candidates.md) |
| Generated supporting outputs | [coverage CSV](../analysis/attack_coverage.csv), [evidence JSON](../analysis/attack_evidence.json), [SHA-256 manifest](../analysis/inventory-manifest.json) |
| Tests | `tests/test_evidence_inventory.py` |
| Updated documentation | `README.md`, `analysis/technique_selection.md`, `docs/dataset.md`, `docs/sanitization.md`, `docs/correlation.md`, `docs/evaluation.md`, `docs/limitations.md`, this record |

The full dataset stays Git-ignored. Raw source bytes remain unchanged. The root ZIP is
no longer present at final review; no current V4 member was removed. Both the combined
and period exports contain useful representation evidence, and the remaining publisher
files document provenance and label derivation.

## Key findings

- The period corpus contains **102,011 distinct documents**, across **16 files**.
  `combined.csv` and the mapping CSV each contain another representation of these rows,
  not another set of independent events. There are **36** manifest scenarios.
- Observed channels include Sysmon, Application, System and Security, plus Wazuh
  infrastructure/FIM/SCA records. Agent names and originating computers remain separate.
- Wazuh event annotations contain **24 parent techniques and 21 sub-techniques**.
  The broader text inventory contains **112 parent-shaped and 172 sub-technique-shaped
  IDs**; references do not establish execution. Per-ID counts and evidence are in coverage.
- All **102,011** mapping rows join to period-file name plus zero-based parsed row index,
  with matching timestamp, agent and technique values. Attribution is derived from
  labels and context; **89,820** rows have `SHARED-WEAK` attribution. No independent
  per-event malicious/benign labels or authoritative execution boundaries were found.
- All source/combined document IDs align, but **65,337** payloads differ across
  **19 fields**. Differences include partial clocks, numeric precision, lost leading
  zeros, case changes and spreadsheet-like error values. Only **36,674** payloads match
  exactly after aligning nonempty columns. Neither representation is uniformly lossless.
- Explicit Windows UTC timestamps occur on **90,601** documents. Display clocks lack
  timezone information. Of **65** numeric-time comparisons against embedded originals,
  **57** are within one second under an Excel-date hypothesis; **8** lack the required
  full-date information. A blanket numeric-date conversion is unsupported.
- Zero structural parsing rejects or exact duplicate period rows were found. This does
  not establish complete telemetry or correct technique annotations.

## Correlation candidates and limits

Promising contexts for later behavioural review include `T1059.001` + `T1059.003`
(83 parent-child observations within 300 seconds), `T1053.005` + `T1059.003`
(73 same-GUID and 34 parent-child observations), and `T1059.003` + `T1548.002`
(34 parent-child observations). These counts require separate documents with distinct
label sets. They are exploratory counts, not confirmed malicious sequences, and relation
categories must not be added as unique alerts.

Source examples show shell-to-PowerShell execution, a task-creation command linked to
`taskschd.dll` loading, and an auto-elevated utility linked to a shell child. They also
show ordinary administration candidates and misleading labels. A module load is not
proof of task registration, and a deletion label on `updater.exe -Command exit` is not
proof of file deletion. The two largest unfiltered structural combinations have zero
exclusive-label pairs. No final three techniques or executable correlation rule is chosen.

## Verification

Commands run from the project root:

```powershell
.\.venv\Scripts\python.exe -m src.preprocessing.inspect_dataset --output analysis/dataset_schema.json
.\.venv\Scripts\python.exe -m src.preprocessing.evidence_inventory --reuse-schema
.\.venv\Scripts\python.exe -m pytest --basetemp .test-tmp/workflow-check-review -q
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m pip check
```

- **39 tests passed**. The ten dataset inspection tests cover discovery, schema/null statistics,
  bounded examples/distinct counts, timestamp ambiguity, exact ATT&CK token boundaries,
  parent/sub classification, reference separation, source/combined differences, verified
  scenario joins, source preservation, deterministic generation, cache invalidation,
  distinct-event correlation and Markdown escaping. Existing tests cover malformed
  CSV/JSON/JSONL, encoding failure, partial scans and source-write protection.
- Ruff lint and formatting checks passed; `pip check` found no broken requirements.
- All **28/28** source files still match preparation-time byte counts and SHA-256 values;
  all **20/20** publisher CSV checksums match. Full generation checks input hashes both
  before and after analysis. Generator and output hashes are in the dataset inspection manifest.
- All seven generated artifacts were regenerated byte-identically using the verified
  schema cache. The small fixture integration test also compares complete generation
  against cached generation. Required reports and evidence excerpts were inspected.

Docker infrastructure checks belong to [environment setup](project-scaffold-and-environment.md); this checkpoint did not yet include ingestion or runtime detection/dashboard results. The processed directory then contained only `.gitkeep`; subsequent workflows implemented normalization and queries.

## Completion evidence and data normalization questions

| Requirement | Authoritative evidence |
|---|---|
| File inventory, formats, sizes, counts, parsing | `dataset_schema.json` file inventory/profiles; `dataset_inventory.md` |
| Real fields, types, nulls, distinct values, timestamps, JSON | Per-file field profiles in `dataset_schema.json` |
| All technique IDs, event/reference separation, sub-technique evidence | `attack_coverage.md`, `.csv`, and `attack_evidence.json` |
| Scenarios, joins, truth and boundaries | Corpus mapping checks, manifest/validation tables and truth caveats |
| Related events, counts, keys, times, suitability | Correlation candidates, source excerpts and all-candidate ratings |
| Proposed ECS fields with confidence and reasons | `ecs_mapping_candidates.md`; source fields checked against inventory |
| Software correctness and reproducibility | Tests, full-data regeneration and `inventory-manifest.json` |
| Preserve raw data and stop at dataset inspection | Raw hashes and the preserved pre-transformation inventory checkpoint |

The subsequent normalization workflow implements a documented source/provenance and record-conservation contract,
prefer explicit Windows event time, preserve nanosecond source precision and unresolved
timestamps, validate escaped strings/numeric types, and apply provider-aware ECS mapping.
It must keep original evidence and derived labels separate from future detector inputs.
The completed [normalization record](data-sanitization-and-ecs-normalization.md) resolves the transformation policy, while the detection and evaluation records explain behavioral validation and uncertainty.
