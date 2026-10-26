# T1059.003 — Windows Command Shell

Tactics: Execution. Validated: 2026-09-16T12:50:04.356335+00:00.

## Objective and observable telemetry

cmd.exe process creation whose same record has services.exe ancestry plus a PowerShell executable in its command, or an sc create/config command assigning an interpreter-valued binPath.

Provider/event codes: `{'Microsoft-Windows-Sysmon': ['1']}`.

The baseline requires Sysmon process creation (provider plus event 1) and cmd.exe. It retains ordinary command-shell activity, including /c commands and routine directory changes.

Predicate fields: `event.provider`, `event.code`, `process.name`, `process.command_line`, `process.parent.name`.

Output fields: `event.id`, `@timestamp`, `host.name`; flags are returned where applicable. Process-name and installation baselines do not require command text; service-command baselines and refinements do. The shell ancestry branch also needs `process.parent.name`. Missing fields fail their positive condition without failing another independently satisfied OR branch. Missing timestamps do not prevent an individual match.

Supporting evidence retains `user.name`, `process.executable`, parent command/name, process/parent entity IDs and source-file/row/hash provenance where present. These fields are context unless explicitly listed in the executable predicate.

## Executable queries and counts

Matching unit: **distinct event.id**. Raw rows are counted before export; full ID sets give exact host and event counts. Event observations are not attacks.

| File | Role / cohort | Raw rows | Distinct events | Hosts | First / last UTC |
|---|---|---:|---:|---:|---|
| [baseline.esql](baseline.esql) | baseline / process_creation | 7717 | 7717 | 3 | 2024-11-05T10:48:57.8075783Z / 2024-12-22T12:53:50.1888457Z |
| [detection.esql](detection.esql) | refined / process_creation | 172 | 172 | 3 | 2024-11-05T13:34:51.2080098Z / 2024-12-14T17:30:59.5689515Z |
| [detection.kql](detection.kql) | review_filter / process_review | 7717 | 7717 | 3 | 2024-11-05T10:48:57.8075783Z / 2024-12-22T12:53:50.1888457Z |

Coarse process/command-presence review filter only; not equivalent to refined ES|QL. KQL cannot reproduce TO_LOWER plus token-pattern logic faithfully.

## Baseline versus refinement

Require services.exe as parent plus a PowerShell executable mention, or an sc create/config command with an interpreter mentioned after binPath=. Neither /c nor a rare parent alone qualifies. The three services-parent records support that branch; service-control command intent supports the other. Routine directory changes and most shell work are removed, but shell abuse outside these service mechanisms is also missed. Strings are inspected as preserved, including escaped quotes and literal &amp;&amp;; no shell parser, executed child or final GUID join is implied.

- `process_creation`: **7717 → 172**, excluding 7545 baseline events. This is candidate-volume reduction only.
- Signal/branch counts (can overlap): `{'inline_command': 149, 'service_control_interpreter': 169, 'interpreter_binpath': 169, 'hidden': 44, 'no_profile': 44, 'service_parent_interpreter': 3}`.
- Representative event IDs: `047897958bacb22c374a7cd75e00d1ff4d497cf10a2c562dde718589d51006ca`, `055b3470e33ad8428e2722bf6a4fb91b1eab9d551fece613b640d0bc07e56b6a`, `06f0d193d8dd0da11d81c1add210986ddb1b8b96ae4f25c5ec56922d117dd795`, `0987d7574011fcd5f3c4d18b35651f0d15c32418de57eefc6d473d74393a1f7f`, `0cf1e60d119adbef05895cb6e3698cdf44991cfcdfc9f9b933ec4a5694892572`, `1ed1ce25b37d60a6adc53a87b8058e51ff77a620b04b333d6bff9d7fad766ec6`, `3154fbb47b3c3efd78fe60f5d197b960a91a267fc38c8db272196e38c200c358`, `8f0564e44cea0da1038e46484c816a8668ee890529fcc83432f6c830a64d3e90`, `c5a93a534cf031f5789b321d070b3f6cf33ec3e79e50b72cf15e384b7821e8e4`.

Deterministic examples and complete queries are in the [generated report](../../analysis/detections/detection-report.md); [results JSON](../../analysis/detections/detection-results.json) retains full evidence fields, all match IDs, missing-field counts and nanosecond ranges.

Routine or ambiguous comparisons:

- `013759f2600917245402d8f22e97bde725d1262bdd8b0a6ec1ba03f28de52002`: Directory-changing shell command has a routine explanation. Retain ancestry; not independently certified benign.

## ATT&CK and CAR grounding

DET0202 / AN0578: Assess shell argument patterns, ancestry and related actions. Local historical baselines are needed before calling a parent unusual.

Dataset Sysmon 1 provides equivalent Process Creation telemetry; CAR also uses process creation and parent fields.

AN0578 lists Security 4688, which is absent here. EDR script-block telemetry is also unavailable; do not claim those feeds exist.

- CAR-2014-11-002 (Outlier Parents of Cmd): Parent-context comparison; historical anomaly thresholds require later testing.
- CAR-2014-05-002 (Services launching Cmd): Service-origin cmd process concept, also relevant to Windows Service.

Official references checked 2026-09-13 UTC:

- [MITRE reference 1](https://attack.mitre.org/techniques/T1059/003/)
- [MITRE reference 2](https://attack.mitre.org/detectionstrategies/DET0202/)
- [MITRE reference 3](https://car.mitre.org/analytics/CAR-2014-11-002/)
- [MITRE reference 4](https://car.mitre.org/analytics/CAR-2014-05-002/)

## False-positive candidates

- Authorized service wrappers and maintenance scripts
- Approved changes assigning interpreters to service commands
- Quoted/echoed commands; substring presence is not full shell parsing

## False-negative, evasion and dataset limits

- Renamed cmd.exe, missing command/parent fields or unsupported quoting/spacing
- Absolute or remote sc invocation forms outside the literal command pattern
- Other shell abuse unrelated to service mechanisms remains outside this refinement

No independent event-level intent truth supports precision, recall, F1 or FPR. The corpus is lab telemetry; command text can include quoted or escaped content. A match requests review and does not establish successful execution or malicious persistence.

## Historical reproduction

Run the [individual detection commands](../../docs/individual-detection-implementation.md#reproduce). Queries cover `windows-apt-events-*` without a wall-clock restriction. All matched events in this validation are timed; 11,410 events elsewhere in the corpus remain undated. Standalone exports are capped at 10,000 rows; use the runner to reject truncation and partial responses. ES|QL is authoritative; no scheduled Security rules have been installed. Child-event joins and final correlation belong to event correlation.
