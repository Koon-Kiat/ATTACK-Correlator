# Correlation methodology and validated results

Status: **event correlation implemented**. Executable queries and the authoritative validator are
in [correlation/](../correlation/README.md); [results](../analysis/correlation/correlation-results.json)
and the [report](../analysis/correlation/correlation-report.md) retain the live evidence.

The primary relationship is a service-origin cmd.exe event followed by a separate
refined PowerShell event. The shell is Sysmon 1, has services.exe as parent and mentions
PowerShell/pwsh in its command. Require exact host equality, shell actor GUID equal to
child parent GUID (case-only normalization), explicit UTC times, strict ordering and an
inclusive upper window bound. A process PID, host/time proximity, scenario or ATT&CK label
is never substituted for GUID ancestry. Source spelling is retained.

| Window | Broad cmd → PowerShell tuples | Refined tuples | Broad participating events | Refined participating events |
|---|---:|---:|---:|---:|
| 60 seconds | 261 | 3 | 483 | 6 |
| 300 seconds | 261 | 3 | 483 | 6 |
| 900 seconds | 261 | 3 | 483 | 6 |

Both cohorts span three hosts. Broad participation is 222 shell and 261 PowerShell
records; twenty shells have multiple children (maximum three). Refined participation is
three shells and three children, with no fan-out. Sixty seconds captures every observed
service-origin lineage tuple even when the comparison search has no cutoff. Counts are
insensitive across the three tested windows; no optimal production window is established.

The exact unit is an ordered tuple of distinct event IDs. A stable SHA-256 ID is computed
from their compact JSON array. Duplicate source IDs fail verification; duplicate tuples
are suppressed. Enumeration preserves fan-out rather than treating a process GUID as one
unique event record. Individual detection counts remain distinct event.id and are never
compared directly with tuple counts as an accuracy measure.

EQL uses per-request runtime date milliseconds plus a nanosecond tiebreaker because the
index stores date_nanos. Its maxspan includes a one-millisecond envelope; Python enforces
`0 < gap_ns <= window × 10^9` from original timestamps. Endpoint predicates are independently
compared with individual detection membership. Broad EQL returns 222 sequences, omitting 39 fan-out
pairs under its one-pending-sequence semantics. The complete validator retains 261.
Refined EQL returns all three exact tuples. ES|QL supplies endpoint/GUID/time coverage
counts, not a temporal join. Runtime fields never change stored data or index mappings.

All three earlier SCM 7045 → cmd → PowerShell relationships still validate, and all three
satisfy current refined endpoints. They involve nine distinct records across three hosts;
none is a current refinement exclusion. Service imagePath is retrieved only from disabled
original `_source` evidence. Full-command case/backslash comparison associates it with the
shell, followed by the GUID join and strict installation/shell/child ordering. The total
three-event span must fit the window. This is a separate evidence-validation path, not an
indexed three-stage EQL rule. No sc.exe counts are added to installation tuples.

For example, the
DESKTOP-FMI6MML triple spans 34,819,700 ns (21,537,200 + 13,282,500), with original IDs and
all three timestamps in the report. The service-origin shell and child observations
strengthen structural evidence; they do not verify persistence, service survival,
requested file creation, command completion or maliciousness.

Candidate tuple volume falls from 261 to 3 by requiring service-origin and refined child
behaviour. This is not a measured false-positive reduction. Authorized marker-file tests
and administrative wrappers can match. Removed broad pairs include encoded-only children
and other shell ancestry; they illustrate valid observable activity outside the refinement,
not proven false negatives. Retain the 287 refined PowerShell events lacking this specific
support and the 169 shell candidates in the other service-control branch as standalone
observations. Missing GUIDs/timestamps/events, other interpreters/parents, renamed/hosted
PowerShell and delayed execution can prevent correlation.

Scenario evaluation replays this validator and selects the earliest installation triple on
**DESKTOP-DS4FBF4 (6 November 2024)** for a bounded demonstration. The other two triples
remain corroboration. [Scenario evidence](../analysis/scenarios/scenario-demonstration.md)
retains exact IDs, service object, GUIDs, nanosecond gaps and provenance. The SCM record
is a baseline installation, outside refined sc.exe process cohorts.

See [evaluation](evaluation.md) for the 11-unit review and evidence preparation, and
the [correlation runbook](event-correlation-validation.md) for replay commands.
The [live dashboard](dashboard.md) implements this evidence contract. Full incident
reconstruction and automated response remain outside scope.
