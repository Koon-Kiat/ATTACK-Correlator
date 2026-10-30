# Detection methodology

Status: **Individual detections, historical correlation and the Kibana dashboard are
implemented**, with live validation recorded in the saved evidence. No scheduled Security rules are installed. See the
[correlation validator](correlation.md) and [dashboard](dashboard.md).

The [technique selection](../analysis/technique_selection.md) and structured contracts remain
authoritative: T1059.001 PowerShell, T1059.003 Windows Command Shell and T1543.003 Windows
Service. The [manifest](../detections/manifest.json) identifies each query, observation
cohort, paired baseline, matching unit, guidance and latest validated count.

## Single-record strategies

| Technique | Baseline | Refined behaviour within one record |
|---|---|---|
| PowerShell | Sysmon 1, PowerShell name: 2,060 | Retrieval + execution indicators, or hidden + no-profile + inline-command switches: 290 |
| Windows Command Shell | Sysmon 1, cmd.exe: 7,717 | services.exe parent + PowerShell mention, or sc create/config with interpreter binPath: 172 |
| Windows Service | SCM 7045: 102 installations | Separate Sysmon 1 sc create commands: 155 → 41; binPath configuration commands: 117 → 108. Sysmon 13 Services ImagePath writes: 708 supporting observations |

Provider and event code establish semantics before executable/name and command content
are considered. PowerShell Bypass and cmd `/c` alone never establish suspicious intent.
Commands and parent fields already present in one record can provide context; separate
child records, GUID joins and EQL sequences are not prerequisites or final rules here.

The two service-command refinements have their own process-event denominators. They are
not subsets of the 102 installation records, and their counts are not added to installation
or registry counts. An observed process, installation and registry write describe different
facts even when later evidence associates them with the same operation.

## Reproducibility and evidence

Use **distinct event.id** for matching. The runner obtains full raw counts before an ES|QL
export capped at 10,000 rows, rejects truncation/partial responses and repeats each query
exactly. Distinct event and host counts use complete sets, without approximate cardinality.
It verifies searchable field capabilities and reads all 11,110 matching IDs back in bounded
batches. An independent source evaluator checks every match and each complete refined set
against its paired baseline, including returned behavioural flags and nanosecond times.

Queries use only observable searchable telemetry. ATT&CK annotations, Wazuh labels,
derived techniques, scenario metadata and disabled original payloads cannot be predicates.
The runner enforces those restrictions and a single-record query shape. Source provenance
is retained for review, independently of detection logic.

Deterministic evidence includes multiple visible command families, event ID, timestamp,
host/user, process/executable, arguments, parent fields and source-file/row/hash provenance.
The [results JSON](../analysis/detections/detection-results.json) contains full fields and match
IDs; the [report](../analysis/detections/detection-report.md) contains concise display excerpts.
Nothing retrieved from the dataset is executed or treated as an instruction.

Use the actual 2024 historical times. Queries impose no wall-clock filter; null timestamps
do not prevent an individual match and are excluded only from min/max. All matched cohorts
are timed, while 11,410 other retained records lack defensible timestamps. Later scheduled
rules need an explicit replay/look-back policy; source times must remain unchanged.

Run the commands in [individual detection](individual-detection-implementation.md#reproduce). The fresh ingestion validation is saved
separately to preserve the earlier report hash required by technique selection. No preprocessing,
ingestion, technique reselection or dataset modification is part of this workflow.

## Guidance and interpretation

Each assigned detection README connects ATT&CK DET0455, DET0202 or DET0552 and the relevant
CAR concept to actual telemetry. Sysmon 1 supplies process creation in place of absent
Security 4688. SCM 7045 supplies installation observations while Security 4697 is absent.
Native PowerShell logs are unavailable. CAR parent/executable concepts guide review;
no clean 30-day baseline, statistical rarity model or full published multi-source analytic
is claimed. ES|QL implements the selected predicates; KQL files are labelled broad review
filters because they do not reproduce the regex/lowercase logic faithfully.

Refinement removes 1,770 PowerShell, 7,545 shell, 114 create-command and 9 configuration
candidates from their respective baselines. This does not measure false-positive reduction.
Approved installers, hidden automation, service maintenance and authorized lab tests can
match. Routine inventory and directory changes, Defender-like installations and restored
service binaries are comparison candidates, not independently verified negatives.

Command patterns cannot prove execution outcome or malicious persistence. Encoded-only or
renamed/hosted interpreters, missing commands/parents, alias/spacing/quoting differences and
API/PowerShell service modification limit coverage. Text in comments or quoted arguments
can match. The high service-config retention reflects repeated similar commands in this
corpus; the [service specification](../detections/technique-3/README.md) explains the
retained and excluded command families.

SCM serviceName/imagePath remain unindexed original fields, retrievable for review only.
No mapping was extended to make an installation-object refinement or join appear available.
Event correlation implements host/GUID correlation with explicit tuple units, fan-out and
missing-support analysis: 261 broad tuples become 3 refined tuples. Standalone candidates
remain available. All three earlier installation corroborations satisfy the refinement. Precision, recall, F1 and FPR
require defensible independent truth and remain unmeasured.
