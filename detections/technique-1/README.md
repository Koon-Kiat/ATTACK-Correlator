# T1059.001 — PowerShell

Tactics: Execution. Validated: 2026-09-16T12:50:04.356335+00:00.

## Objective and observable telemetry

PowerShell process creation whose same command contains retrieval plus execution indicators, or hidden window plus no-profile and inline command switches. No separate event is required.

Provider/event codes: `{'Microsoft-Windows-Sysmon': ['1']}`.

The baseline requires Sysmon process creation (provider plus event 1) and a case-insensitive PowerShell executable name. It measures observed interpreter launches, including approved administration; it does not infer malicious intent.

Predicate fields: `event.provider`, `event.code`, `process.name`, `process.command_line`.

Output fields: `event.id`, `@timestamp`, `host.name`; flags are returned where applicable. Process-name and installation baselines do not require command text; service-command baselines and refinements do. The shell ancestry branch also needs `process.parent.name`. Missing fields fail their positive condition without failing another independently satisfied OR branch. Missing timestamps do not prevent an individual match.

Supporting evidence retains `user.name`, `process.executable`, parent command/name, process/parent entity IDs and source-file/row/hash provenance where present. These fields are context unless explicitly listed in the executable predicate.

## Executable queries and counts

Matching unit: **distinct event.id**. Raw rows are counted before export; full ID sets give exact host and event counts. Event observations are not attacks.

| File | Role / cohort | Raw rows | Distinct events | Hosts | First / last UTC |
|---|---|---:|---:|---:|---|
| [baseline.esql](baseline.esql) | baseline / process_creation | 2060 | 2060 | 3 | 2024-11-05T10:42:56.3186326Z / 2024-12-22T09:13:51.694757Z |
| [detection.esql](detection.esql) | refined / process_creation | 290 | 290 | 3 | 2024-11-05T11:03:49.493885Z / 2024-12-15T13:42:34.2637507Z |
| [detection.kql](detection.kql) | review_filter / process_review | 2060 | 2060 | 3 | 2024-11-05T10:42:56.3186326Z / 2024-12-22T09:13:51.694757Z |

Coarse process/command-presence review filter only; not equivalent to refined ES|QL. KQL cannot reproduce TO_LOWER plus token-pattern logic faithfully.

## Baseline versus refinement

Require retrieval together with execution in the same command, or the combination of hidden window, no-profile and inline-command switches. Retrieval means Invoke-WebRequest, DownloadString, DownloadFile or bounded iwr; execution means Invoke-Expression, bounded iex or Start-Process. Bypass alone, inventory commands, encoded-only commands and download-only scripts are excluded. Approved installers can satisfy both retrieval and execution; hidden marker-file automation can also match. The omitted events include valid PowerShell activity, so lower volume does not demonstrate improved accuracy.

- `process_creation`: **2060 → 290**, excluding 1770 baseline events. This is candidate-volume reduction only.
- Signal/branch counts (can overlap): `{'retrieval_and_execution': 287, 'hidden_no_profile_inline': 3}`.
- Representative event IDs: `0139e7fcfc5b9bffc583128a7d46c35f829d2c075cd365dd94c606ba7d04ff81`, `02dd549303cf8ecf28c09e4889489270e83633166d02f5e0802da5b40435fcf5`, `02f17931b2999dd857b387b8e4f86d834143382d7d8948456029e2571254a791`, `0405e4890856e5219b7621b29478f2b59633624262f74dead0771d6dee3f2691`, `04fe2480cf829f94e59e56ad57c500219894f757d622d67f8b4ab4a250c181d1`, `3faf8b4d35dd5fcb924ed44ed7e10d944f2b84243f9bf6f98c07b4e4b4d8d00d`, `c87894aacb7c79e770e4eb8b1fd95fcf9612bb5fddba0c3f00edea3a9a9d6634`.

Deterministic examples and complete queries are in the [generated report](../../analysis/detections/detection-report.md); [results JSON](../../analysis/detections/detection-results.json) retains full evidence fields, all match IDs, missing-field counts and nanosecond ranges.

Routine or ambiguous comparisons:

- `4ea94313bd0565c1a29ba059663e5824ebe4f2b9a7e25e1430f451017feef75c`: Process inventory with Bypass has routine command semantics; its Public-directory splunkd.exe parent remains suspicious. Ambiguous comparison, not a known benign event.

## ATT&CK and CAR grounding

DET0455 / AN1252: Inspect interpreter arguments and ancestry together with module, network or child-process observations; direct and hosted PowerShell require different coverage.

Sysmon 1 process creation; Sysmon 7 module telemetry exists; other mapped supporting events can be explored.

Native PowerShell provider logs, including 4103/4104/4105/4106 and 400/403, were not observed.

- CAR-2014-04-003 (Powershell Execution): Process creation and non-interactive parent context; an explorer-parent exclusion is a contextual concept, not copied as a final rule.

Official references checked 2026-09-13 UTC:

- [MITRE reference 1](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE reference 2](https://attack.mitre.org/detectionstrategies/DET0455/)
- [MITRE reference 3](https://car.mitre.org/analytics/CAR-2014-04-003/)

## False-positive candidates

- Approved download-and-run administration or software bootstrap scripts
- Authorized hidden automation and marker-file tests
- Quoted, commented or echoed indicators without executing the represented action

## False-negative, evasion and dataset limits

- Native PowerShell 400/403/4103/4104 telemetry absent
- Renamed or in-process PowerShell and encoded-only commands
- Aliases, alternate spacing, string construction and missing command content
- Downloads and execution split across events are intentionally outside this rule

No independent event-level intent truth supports precision, recall, F1 or FPR. The corpus is lab telemetry; command text can include quoted or escaped content. A match requests review and does not establish successful execution or malicious persistence.

## Historical reproduction

Run the [individual detection commands](../../docs/individual-detection-implementation.md#reproduce). Queries cover `windows-apt-events-*` without a wall-clock restriction. All matched events in this validation are timed; 11,410 events elsewhere in the corpus remain undated. Standalone exports are capped at 10,000 rows; use the runner to reject truncation and partial responses. ES|QL is authoritative; no scheduled Security rules have been installed. Child-event joins and final correlation belong to event correlation.
