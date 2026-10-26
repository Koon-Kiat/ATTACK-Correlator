# Individual detection implementation

This engineering record preserves the observations and checks for this workflow.
For the completed implementation and current status, see the [project README](../README.md).

Date: 13 September 2026, Singapore. **Individual detections are implemented and
validated against Elasticsearch 9.5.3.** technique selection's three selections remain authoritative.
No final multi-event correlation, scheduled Security rules or dashboard is included.

## Results

All counts below are **distinct event.id**, equal to the raw returned row counts.
All matched events have historical timestamps. The generated
[report](../analysis/detections/detection-report.md) records each query's host count,
nanosecond time range and evidence IDs; the [JSON](../analysis/detections/detection-results.json)
retains complete match sets, evidence projections, source provenance and query hashes.

| Technique / observation | Baseline | Refined | Excluded candidates | Baseline / refined hosts |
|---|---:|---:|---:|---|
| T1059.001 PowerShell process creation | 2,060 | 290 | 1,770 | 3 / 3 |
| T1059.003 Windows Command Shell process creation | 7,717 | 172 | 7,545 | 3 / 3 |
| T1543.003 SCM 7045 installations | 102 | Separate process variants below | Not comparable | 4 / — |
| T1543.003 sc.exe create commands | 155 | 41 | 114 | 3 / 3 |
| T1543.003 sc.exe binPath configuration commands | 117 | 108 | 9 | 3 / 3 |
| T1543.003 Services ImagePath registry writes | 708 | Supporting baseline only | Not applicable | 3 / — |

PowerShell requires retrieval plus execution indicators in the same command (287
events), or hidden window + no-profile + inline command switches (3 events). These
branches do not overlap in this corpus. ExecutionPolicy Bypass alone is insufficient.
The 290 matches include download-and-run commands and hidden marker-file creation;
authorized administration, software installers and lab tests remain plausible.

The shell refinement requires services.exe parent context with a PowerShell executable
in the same command (3 events), or sc create/config intent with an interpreter after
binPath= (169 events). These branches do not overlap here. `/c` alone and parent rarity
alone do not qualify. Routine directory changes are excluded, as is shell abuse outside
the selected service mechanisms. No child process or GUID join is required.

Service refinements inspect sc.exe create and config independently for interpreter
mentions after binPath=. This retains 41 interpreter-wrapper creation commands and
108 PowerShell configuration commands. The nine excluded configuration records restore
fxssvc.exe. Excluded create records also include test executables, illustrating lost
coverage rather than certified benign activity. The high 108/117 retention reflects
the homogeneous observed configuration commands; it is not a claim of high precision.
Neither process variant is a subset of SCM 7045 records, and the cohorts are never summed
or presented as unique service operations or attacks.

## Representative evidence

These are individual records, not a reconstructed sequence. Full fields and additional
deterministic examples are retained in the generated results, including multiple command
families and explicit ambiguous comparisons.

| Event ID | Behaviour / comparison |
|---|---|
| `0139e7fcfc5b9bffc583128a7d46c35f829d2c075cd365dd94c606ba7d04ff81` | PowerShell command contains IEX and iwr retrieval; splunkd.exe parent retained |
| `047897958bacb22c374a7cd75e00d1ff4d497cf10a2c562dde718589d51006ca` | cmd command requests sc config with PowerShell binPath, followed by textual service start |
| `01a39aaa0ab4f30ba0883fad92598d99a9347baed6a395936abbda41ae2bd09a` | sc create assigns cmd/PowerShell marker-file command |
| `014b4475343bcdf621c664c5caf7d29448162ee516d406ce2048197e2ae9540f` | sc config assigns PowerShell with a test message to Fax |
| `4ea94313bd0565c1a29ba059663e5824ebe4f2b9a7e25e1430f451017feef75c` | PowerShell inventory has routine semantics but ambiguous parent context |
| `013759f2600917245402d8f22e97bde725d1262bdd8b0a6ec1ba03f28de52002` | Routine directory-changing shell comparison |
| `0b1f6f98acb0185bf38e6311eff2d76c0f98da7c178dea8dbe3fecc074ab9f7e` | Defender Definition Updates driver installation; legitimate-update candidate |

## Guidance and limitations

The assigned [PowerShell](../detections/technique-1/README.md),
[shell](../detections/technique-2/README.md) and
[service](../detections/technique-3/README.md) specifications connect the executable
predicates to ATT&CK DET0455/AN1252, DET0202/AN0578 and DET0552/AN1527, with relevant
CAR process/parent and service-executable concepts. Official references were checked on
13 September 2026 UTC. Sysmon 1 substitutes for absent Security 4688 process creation;
SCM 7045 provides service-installation observations while Security 4697 is absent.

Native PowerShell logging is absent. Renamed or hosted interpreters, encoded-only
commands, unrecognized aliases/spacing, missing command lines and service changes through
APIs or PowerShell can evade these refinements. The patterns inspect preserved command
text, including escaped quotes and literal `&amp;&amp;`; they do not parse or execute it.
Comments and quoted mentions can match. No command match proves its requested outcome.
Service object fields remain unindexed original evidence, retrieved only for review.

Lower candidate volume is not a measured false-positive reduction. No independent
event-level intent truth supports precision, recall, F1 or FPR. The full corpus retains
11,410 unresolved timestamps; no timestamp was invented or rewritten for detection.

## Reproduce

From the repository root, with the existing local stack running:

```powershell
.\.venv\Scripts\python.exe scripts/check_stack.py
.\.venv\Scripts\python.exe scripts/validate_ingestion.py --output-directory analysis/detections/prerequisites
.\.venv\Scripts\python.exe scripts/verify_technique_selection.py
.\.venv\Scripts\python.exe scripts/run_individual_detections.py
.\.venv\Scripts\python.exe -m pytest -q --basetemp .test-tmp/workflow-check
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m pip check
```

On Bash use `.venv/bin/python`. If Docker is stopped, start it and wait for existing
services to become healthy. The retained Logstash configuration can automatically replay
its input on restart; wait until its 102,011 input/output operations drain and health is
green before validation. Stable IDs preserve the index count. No ingestion command,
preprocessing rerun, dataset mutation or mapping change is required for individual detection.

The ingestion validation validator first runs existing data normalization integrity/conservation verification;
this verifies processed data without regenerating it. Its output-directory option keeps
the original ingestion validation report unchanged because technique selection checks that report's exact hash.
The fresh replay is saved under `analysis/detections/prerequisites/` and hashed by individual detection.
technique selection verification replays existing selection evidence, including earlier exploratory
relationships; this does not implement or extend event correlation.

The detection runner executes **10 ES|QL queries and 3 KQL review filters**, repeating
each and comparing complete returned rows. A full count before the export limit prevents
silent truncation. All **11,110 distinct matching IDs** are read back in batches, and
each refined set is independently checked against its baseline source projections. Field
capabilities, IDs, host values, nanosecond timestamps and returned behavioural flags are
verified. Missing field counts and deterministic evidence are retained. KQL files are
coarse review filters, not equivalents of the authoritative ES|QL regex refinements.

The runner regenerates the manifest's validated counts, three detection READMEs and both
results artifacts. It invalidates a previous result/report before a new attempt; a failed
or interrupted run must be resolved before calling individual detection complete.

## Recovery findings and checks

The interrupted implementation contained executable query files and a draft runner/
manifest, but its results JSON only said validation had started. All three READMEs were
unassigned, the report and individual detection documentation were absent, and tests were missing.

Recovery found an actual runner failure: one evidence request contained more than
Elasticsearch's allowed 10,000 IDs. Bounded 1,000-ID readbacks now verify every requested
ID without changing cluster limits. Focused tests cover that failure, missing IDs,
truncation, duplicate identity accounting, nanosecond order, source/flag contradictions,
missing fields, predicate independence, correct slots and service-cohort separation.
The validator output option is tested to preserve the original report byte-for-byte.

Live ingestion validation passed at **102,011 total / 90,601 timed / 11,410 undated**. technique selection passed
**29 query replays and 141 evidence projections across 114 IDs**, with all selected
contracts unchanged. All 13 individual detection query executions and exact repeats passed.
The final checks passed: **136 pytest tests**, Ruff lint, Ruff formatting (**35 Python
files**) and `pip check` (no broken requirements). Tests contain synthetic software
fixtures only.

## Files and related workflows

- `detections/technique-1/`, `technique-2/`, `technique-3/`: assigned READMEs, executable
  baseline/refined ES|QL, KQL review filters; separate service comparison files.
- `detections/manifest.json`: query inventory, guidance, cohorts and validated counts.
- `scripts/run_individual_detections.py`, `tests/test_individual_detections.py`: historical
  runner, evidence export, report generation and focused regression tests.
- `scripts/validate_ingestion.py`, `tests/test_ingestion.py`: separate replay destination.
- `analysis/detections/`: results JSON, report and fresh ingestion validation prerequisite replay.
- `analysis/selection/selection-verification.json`: refreshed existing live verification.
- `README.md`, `docs/detection-methodology.md`, `docs/limitations.md`,
  `docs/architecture.md`, this record:
  consistent completion status and reproducible methodology.

The implemented [event correlation](event-correlation-validation.md) uses a host-scoped process GUID / parent GUID join for
service-origin cmd → PowerShell, with explicit historical windows and distinct ordered
event-ID tuple units. Preserve standalone candidates and evaluate delayed/missing-event
behaviour. SCM installation-object confirmation needs a separately reviewed extraction
decision because those object fields remain unindexed. The correlation and scenario workflows document the completed source-only extraction and validation.
