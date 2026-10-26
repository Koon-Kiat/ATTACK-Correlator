# Data sanitization and ECS normalization

This engineering record preserves the observations and checks for this workflow.
For the completed implementation and current status, see the [project README](../README.md).

Date: 2026-09-12. Scope: data sanitization, normalization, ECS mapping and a verified
processed dataset. Subsequent ingestion is documented in [Elastic ingestion and validation](elastic-ingestion-and-validation.md).

## Implementation

Replaced the `clean.py`, `normalize.py` and `enrich.py` placeholders and added the
streaming `preprocess.py` command, `elastic_contract.py` offline mapping definition and
`verify_processed.py` source-readback verifier. The implementation uses the verified
dataset inspection canonical file list and a temporary disk-backed scenario index. No source data
is altered, and combined/mapping exports are never counted as additional events.

The pipeline preserves original field values, identifiers, source hashes and row
locations. Exact empty cells are reconstructed from the retained source schema;
whitespace and literal null strings remain intact. Each source row produces an event
or an explicit rejection. Timestamp/type conversion and provider-aware field mapping
operate separately from source annotations and publisher scenario attribution.
The complete transformation policy is in [sanitization.md](sanitization.md).

## Created and modified files

| Area | Files |
|---|---|
| Implemented modules | `src/preprocessing/clean.py`, `normalize.py`, `enrich.py` |
| Added modules | `src/preprocessing/preprocess.py`, `elastic_contract.py`, `verify_processed.py` |
| Tests | `tests/test_preprocess.py` |
| Generated reports | [preprocessing report](../analysis/preprocessing_report.md), [summary JSON](../analysis/preprocessing_summary.json), [data normalization manifest](../analysis/normalization-manifest.json) |
| Ignored processed artifacts | `dataset/processed/windows-apt-events.ndjson`, `source-schemas.json`, `publisher-metadata.json`, `elastic-mapping.json` |
| Documentation | `README.md`, `docs/sanitization.md`, `docs/architecture.md`, `docs/limitations.md`, `elasticsearch/templates/README.md`, this record |

Existing ignore rules already exclude all raw and processed data while retaining both
`.gitkeep` files, so no additional ignore pattern was necessary. Raw files, dataset inspection
generated evidence, ingestion stubs, detection/correlation placeholders and dashboard
scaffolds remain unchanged. No commits, remote publication or installation was requested.

## Dataset results

The generated report/summary are the authoritative field-by-field statistics.

| Check | Result |
|---|---|
| Canonical input | 102,011 rows in 16 period CSVs |
| Distinct original source identities | 102,011 |
| Processed output | 102,011 events |
| Rejected output | 0; no rejection file is emitted |
| Exact duplicate canonical documents | 0 |
| Conflicting source identities | 0 |
| Conservation | 102,011 = 102,011 + 0 |
| Explicit UTC timestamps | 90,601, retaining original fractional precision |
| Validated fallback timestamps | 0 |
| Unresolved timestamps | 11,410, flagged with no invented @timestamp |
| Scenario mapping joins | 102,011; no missing source rows |
| Source ATT&CK annotations | 63,619 events; stored separately from ECS observations |
| Wazuh annotation coverage | 102,011 events |
| SHARED-WEAK attribution | 89,820 events; never presented as independent truth |
| Invalid mapped IP/port/PID numeric values | 0 / 0 / 0 |

Mapped fields include host/agent/source-rule identifiers, event code/provider, process
and parent executable/name/command/PID/GUID, process/module hashes, file and registry
paths, network endpoints, DNS query names and clearly identified actor accounts. Sysmon
process-access source context and Security 4624/4625 caller context use their own reviewed
source fields. Target accounts/processes remain separate original evidence. No event
category/type or maliciousness/risk score is fabricated.

The run flags zero GUIDs rather than treating them as process identities. A zero caller
PID in Security logon events stays unresolved. A DNS timeout supplies a queried name,
not a successful response. Other unreviewed contexts remain original with warnings.
The NDJSON is relatively large because the source contains many space-filled cells;
preserving those exact values is intentional. No complete dataset was duplicated for tests.

## Validation

```powershell
.\.venv\Scripts\python.exe -m src.preprocessing.preprocess
.\.venv\Scripts\python.exe -m src.preprocessing.verify_processed
.\.venv\Scripts\python.exe -m pytest -q --basetemp .test-tmp/workflow-check-code
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m pip check
```

- **76 tests passed**, including all existing environment setup and dataset inspection tests and 37 data normalization cases.
  Coverage includes raw/artifact hash guards, read-only handling, conservation and
  rejections, nanosecond timestamps and unresolved times, quoted/UNC/malformed Windows
  paths, process names, decimal/hex PIDs, IPs/ports, GUID preservation, hash object context
  and conflicts, booleans, actor/target separation, provider gates, file/registry/DNS
  distinctions, annotations, scenario joins, provenance, original-value reconstruction,
  duplicate retention, deterministic output, and detection of modified output files.
- Ruff lint and formatting checks passed. `pip check` found no broken requirements.
- Two complete runs of the final implementation produced identical processed-output,
  report and manifest hashes. No generation timestamps or temporary paths are embedded
  in reproducible artifacts. Python and processing versions are recorded explicitly.
- The independent verifier streamed every output/rejection against its actual raw row,
  checked exact original reconstruction, complete source accounting, all published
  hashes and the offline mapping contract. Its machine-readable result is retained in
  ignored `analysis/inspection/normalization-verification.json`.
- Raw source hashes remain identical to dataset inspection before and after processing. The
  publisher checksum verification remains applicable because source bytes are unchanged.

The offline mapping validates local types and structure only. No Elasticsearch ingestion,
query execution, detection accuracy, dashboard or live-server compatibility is claimed.

## Completion evidence

| Required property | Evidence |
|---|---|
| Canonical source verification and no double-counting | dataset inspection hash guard, period-file list, exact count comparison |
| All source rows accounted for | Summary conservation counts plus independent sequential readback |
| Raw evidence unchanged | Full raw SHA-256 comparison before/after and independent verification |
| Traceable, lossless processed evidence | Per-row provenance, original-row hashes, source-schema sidecar and reconstruction |
| Safe timestamps and types | Strict converters, full-run quality counts and positive/negative tests |
| Semantically valid ECS fields | Provider-aware projection, documented exceptions, offline contract and tests |
| Separate source labels and derived metadata | Dedicated annotation/scenario namespaces, publisher sidecar and isolation tests |
| Elastic-ready NDJSON | UTF-8/LF JSON, explicit mapping contract and full-output type validation |
| Reproducibility | Source/code/config/output/report manifest plus identical full-run hashes |
| Accurate project documentation | Generated reports, transformation policy and this validation record |

## Limitations and ingestion contract

No fallback timezone is justified for the 11,410 unresolved timestamps. Original
backslash/case spelling is preserved; future comparisons must account for Windows
case/escaping without destroying original evidence. Unsupported contexts and invalid
identities stay visible. Scenario labels are derived and unsuitable as independent
binary truth for precision, recall or F1.

The implemented ingestion workflow verifies the normalization manifest, installs the
offline mapping contract, preserves `date_nanos` and original `_source` payloads, and
uses authenticated Logstash ingestion with deterministic IDs. Input/output accounting
and an explicit reject route check server acceptance. Undated events receive no
fabricated current timestamp. The README links the completed detection, correlation
and dashboard workflows.
