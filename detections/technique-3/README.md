# T1543.003 — Windows Service

Tactics: Persistence, Privilege Escalation. Validated: 2026-09-16T12:50:04.356335+00:00.

## Objective and observable telemetry

Separate sc.exe create and config process variants with an interpreter mentioned after binPath=. SCM 7045 and Services ImagePath writes remain distinct observational baselines; no searchable installation-object refinement is claimed.

Provider/event codes: `{'Microsoft-Windows-Sysmon': ['1', '13'], 'Service Control Manager': ['7045']}`.

The primary baseline uses Service Control Manager 7045 installation semantics. Separate Sysmon 1 sc.exe create and binPath configuration baselines supply like-for-like denominators for their refinements. Sysmon 13 Services ImagePath writes form a supporting cohort. No count is subtracted from 102 installations or summed across these cohorts.

Predicate fields: `event.provider`, `event.code`, `process.name`, `process.command_line`, `registry.path`.

Output fields: `event.id`, `@timestamp`, `host.name`; flags are returned where applicable. Process-name and installation baselines do not require command text; service-command baselines and refinements do. The shell ancestry branch also needs `process.parent.name`. Missing fields fail their positive condition without failing another independently satisfied OR branch. Missing timestamps do not prevent an individual match.

Supporting evidence retains `user.name`, `process.executable`, parent command/name, process/parent entity IDs and source-file/row/hash provenance where present. These fields are context unless explicitly listed in the executable predicate.

## Executable queries and counts

Matching unit: **distinct event.id**. Raw rows are counted before export; full ID sets give exact host and event counts. Event observations are not attacks.

| File | Role / cohort | Raw rows | Distinct events | Hosts | First / last UTC |
|---|---|---:|---:|---:|---|
| [baseline.esql](baseline.esql) | baseline / service_installation | 102 | 102 | 4 | 2024-11-05T10:54:14.4669595Z / 2024-12-22T11:05:33.0936847Z |
| [baseline-create.esql](baseline-create.esql) | comparison_baseline / service_create_process | 155 | 155 | 3 | 2024-11-05T13:35:33.3145881Z / 2024-12-14T09:01:47.5042143Z |
| [detection.esql](detection.esql) | refined / service_create_process | 41 | 41 | 3 | 2024-11-06T09:58:51.2110964Z / 2024-12-13T00:13:35.9641019Z |
| [baseline-config.esql](baseline-config.esql) | comparison_baseline / service_config_process | 117 | 117 | 3 | 2024-11-05T13:34:51.2709569Z / 2024-12-14T17:30:59.7729986Z |
| [detection-config.esql](detection-config.esql) | refined / service_config_process | 108 | 108 | 3 | 2024-11-05T13:34:51.2709569Z / 2024-12-14T17:30:59.7729986Z |
| [baseline-registry.esql](baseline-registry.esql) | supporting_baseline / registry_write | 708 | 708 | 3 | 2024-11-05T10:39:32.6261111Z / 2024-12-22T12:53:49.226296Z |
| [detection.kql](detection.kql) | review_filter / process_review | 523 | 523 | 3 | 2024-11-05T11:09:46.3661874Z / 2024-12-14T17:30:59.7729986Z |

Coarse process/command-presence review filter only; not equivalent to refined ES|QL. KQL cannot reproduce TO_LOWER plus token-pattern logic faithfully.

## Baseline versus refinement

For sc.exe create and config separately, require an interpreter mention after binPath=. Direct service executables, including potentially suspicious test binaries, are excluded; configuration restoring fxssvc.exe has a routine explanation. A textual mention after binPath is not proof of the parsed executable or service start. SCM serviceName/imagePath remain retrieved, unindexed original fields. The 7045 and registry cohorts remain broad observations rather than falsely claimed refinements.

- `service_create_process`: **155 → 41**, excluding 114 baseline events. This is candidate-volume reduction only.
- Signal/branch counts (can overlap): `{'hidden': 41, 'no_profile': 41, 'inline_command': 41, 'interpreter_binpath': 41}`.
- Representative event IDs: `01a39aaa0ab4f30ba0883fad92598d99a9347baed6a395936abbda41ae2bd09a`, `0542c8f7e5db8c34a87e5c25a8d9c9979595d8bd2aebfa8192480c028e3de65e`, `0d566de0e79482d2096f08c9f36e892a5b926f4c0bb1bb88cedc5bb439390316`.
- `service_config_process`: **117 → 108**, excluding 9 baseline events. This is candidate-volume reduction only.
- Signal/branch counts (can overlap): `{'inline_command': 108, 'interpreter_binpath': 108}`.
- Representative event IDs: `014b4475343bcdf621c664c5caf7d29448162ee516d406ce2048197e2ae9540f`, `01b253be11116c9c6d4b6dac1192fa3942555144a48a8820dd650515646c472c`, `045a928860fec7b58ea4de7d7d01a795ae9ee85fdb411c76faadc571d0177f2c`.

Deterministic examples and complete queries are in the [generated report](../../analysis/detections/detection-report.md); [results JSON](../../analysis/detections/detection-results.json) retains full evidence fields, all match IDs, missing-field counts and nanosecond ranges.

Routine or ambiguous comparisons:

- `0b1f6f98acb0185bf38e6311eff2d76c0f98da7c178dea8dbe3fecc074ab9f7e`: SCM installation uses a Defender Definition Updates driver path. Plausible legitimate update; path appearance is not signature or trust verification.
- `078a375e7354cdc8386ff93052945d498573e06a1f989587a7e6368899b659ff`: sc config Fax assigns fxssvc.exe, consistent with restoring a service binary. Context/authorization is unverified.
- `0487faae790fdea3e8ddbe6d23a87a7cd485da163032b1e9b4a5959adff6f555`: Creation of an AtomicTestService_CMD executable service is excluded because the configured binary is not an interpreter. This illustrates a coverage gap, not a benign verdict.

## ATT&CK and CAR grounding

DET0552 / AN1527: Combine service creation/configuration, registry changes and process lineage; inspect unusual executable locations or service-launched interpreters.

Sysmon 1 and 13 are present. SCM System 7045 supplies service-installation evidence corresponding to the service creation concept.

DET0552 lists Security 4697 and Sysmon 6/14; these are absent. SCM 7045 is the dataset substitution, not falsely described as 4697.

- CAR-2014-05-002 (Services launching Cmd): Direct service-origin shell behaviour, observed in three independent process records.
- CAR-2013-09-005 (Service Outlier Executables): Service executable comparison; no 30-day clean baseline or copied historical pseudocode is claimed.

Official references checked 2026-09-13 UTC:

- [MITRE reference 1](https://attack.mitre.org/techniques/T1543/003/)
- [MITRE reference 2](https://attack.mitre.org/detectionstrategies/DET0552/)
- [MITRE reference 3](https://car.mitre.org/analytics/CAR-2014-05-002/)
- [MITRE reference 4](https://car.mitre.org/analytics/CAR-2013-09-005/)

## False-positive candidates

- Approved service tests, maintenance and interpreter-based service wrappers
- Legitimate Defender/driver and software-update installations in the separate SCM baseline
- An interpreter string in a quoted argument may not be the actual service executable

## False-negative, evasion and dataset limits

- Security 4697 absent; SCM object fields preserved but unindexed
- API/PowerShell service modifications bypass the sc.exe process variants
- Services using direct executables instead of interpreters, including genuinely suspicious creations, are excluded
- Interpreter mention is not proof of service startup, outcome or persistence

No independent event-level intent truth supports precision, recall, F1 or FPR. The corpus is lab telemetry; command text can include quoted or escaped content. A match requests review and does not establish successful execution or malicious persistence.

## Historical reproduction

Run the [individual detection commands](../../docs/individual-detection-implementation.md#reproduce). Queries cover `windows-apt-events-*` without a wall-clock restriction. All matched events in this validation are timed; 11,410 events elsewhere in the corpus remain undated. Standalone exports are capped at 10,000 rows; use the runner to reject truncation and partial responses. ES|QL is authoritative; no scheduled Security rules have been installed. Child-event joins and final correlation belong to event correlation.
