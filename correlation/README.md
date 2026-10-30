# Service-origin shell and PowerShell correlation

Status: executable historical correlation, validated against the existing Elastic 9.5.3
index. Selected sub-techniques remain T1059.001 PowerShell, T1059.003 Windows Command Shell
and T1543.003 Windows Service. No scheduled Security rule is installed. The
[implemented dashboard](../docs/dashboard.md) presents the validated correlation evidence.

## Primary relationship

A Sysmon 1 `cmd.exe` event with `services.exe` as parent and PowerShell/pwsh in its command
must precede a separate individual detection refined PowerShell event. Require exact `host.name`
equality and shell `process.entity_id` = child `process.parent.entity_id`, comparing GUID
case only. Braces/separators are not changed. Missing/invalid/zero GUIDs do not join.
Only explicit valid UTC timestamps qualify, with **0 < gap_ns <= window × 10^9**.
The shell endpoint is specifically the service-origin branch of the existing shell rule.
The other service-control branch is not substituted for it.

Default window: **60 seconds**, with 300/900-second sensitivity checks. All three
service-origin lineage tuples found without a time cutoff fit within 60 seconds; this
supports the dataset default, not a claim about an optimal production setting.

The matching unit is an **ordered tuple of distinct event IDs**. Stable `correlation_id`
is SHA-256 of the compact UTF-8 JSON array of ordered IDs. The validator rejects duplicate
source IDs, enumerates all eligible pairings and suppresses duplicate tuples. It also
reports unique participating events/hosts and fan-out. It never joins on host/time alone.

## Executable artifacts

| Artifact | Role |
|---|---|
| [correlation.eql](correlation.eql) | Refined service-origin cmd → refined PowerShell sequence view |
| [baseline.eql](baseline.eql) | Broad cmd → PowerShell sequence view with identical structural keys |
| [eql-request.json](eql-request.json) | Complete default refined EQL request, including temporary runtime fields |
| [correlation.esql](correlation.esql) | Endpoint counts and timestamp/GUID coverage; not a temporal join |
| [manifest.json](manifest.json) | Selected contracts, windows, query inventory and frozen individual detection query hashes |
| [run_correlation.py](../scripts/run_correlation.py) | Authoritative exact event-set/UTC/GUID validation and full tuple enumeration |

`date_nanos` is not supported as an EQL timestamp. The request defines a millisecond
`date` and an integer-nanosecond tiebreaker, plus lowercase command/name/GUID fields. These
exist only during that search; the index mapping and stored source are unchanged. EQL's
maxspan is **60001ms** for the 60-second evaluation: a one-millisecond search envelope
protects the inclusive boundary after millisecond conversion. The validator enforces the
exact 60-second bound and strict ordering using the original UTC timestamps.

Both EQL endpoint predicates are independently run and compared with the exact individual detection
sets: 3 service-origin shell events and 290 refined PowerShell events. Pattern membership
matches on the corpus. EQL sequence state is still not equivalent to an exhaustive join:
one pending sequence per join key/state can omit fan-out pairs. Python is authoritative.

## Results and evidence units

| Window | Broad tuples | Refined tuples | Broad unique events / hosts | Refined unique events / hosts |
|---|---:|---:|---|---|
| 60 seconds | 261 | 3 | 483 / 3 | 6 / 3 |
| 300 seconds | 261 | 3 | 483 / 3 | 6 / 3 |
| 900 seconds | 261 | 3 | 483 / 3 | 6 / 3 |

Broad tuples use 222 shell and 261 PowerShell events. Twenty shells participate in
multiple tuples, with a maximum of three children. The broad EQL view returns 222
sequences and omits 39 fan-out pairs; these are retained by the validator. Refined tuples
use three shell and three PowerShell events, without fan-out. The refined EQL view returns
all three. Counts are insensitive across these tested windows only.

## Three-technique corroboration

All **three** previously observed SCM 7045 → services-origin cmd → PowerShell
relationships revalidate, and **all three satisfy the current refined endpoints**.
No known three-event relationship is excluded by refinement in this corpus.

The validator retrieves SCM `imagePath` from preserved `windows_apt.original` via `_source`.
It compares the full service image command with the shell command after case folding,
trimming outer whitespace and collapsing repeated backslashes, then checks GUID ancestry,
strict installation < shell < child ordering and total span within the window. Internal
whitespace, HTML entities and quoted command semantics are not decoded or executed.
This lexical comparison can conflate some Windows path spellings and is an object
association, not proof of a specific service API call. Original strings are retained.

Installation, observed service-origin execution and a separate child event supply stronger
structural evidence than installation alone. The triples involve nine distinct events
across three hosts. They do not prove persistence succeeded, service survival, command
completion, file creation or malicious intent. The separate sc.exe create/config variants
remain individual process observations and are not added to these installation tuples.

## False-alarm and missed-detection considerations

Refinement removes 258 of 261 broad candidate tuples through additional behavioural
requirements. Standalone PowerShell, cmd and service installations have routine uses;
actual GUID-linked service-origin interpreter events provide more specific context.
Authorized service tests, marker-file automation and administration can still satisfy
the full correlation. No event-level intent truth establishes false-positive counts.

Known triples are not excluded, but the removed broad examples include encoded-only
PowerShell with genuine cmd ancestry. These are technique-consistent relationships
outside the chosen refinement, not confirmed false negatives. There are 287 refined
PowerShell events without this service-origin shell tuple and 169 refined shell events
in the other service-control branch. Keep individual candidates available for review.

Missing process records/GUIDs, unresolved timestamps, renamed or in-process PowerShell,
other parents, other interpreters, direct service executables, installation without
captured execution, gaps beyond the window and individual detection's deliberately narrow commands
all limit coverage. Thirty-nine baseline PowerShell records lack a usable parent GUID.
No precision, recall, F1, FPR, confusion matrix or numeric confidence score is asserted.
Use “standalone behavioural candidate”, “strong structural correlation candidate”, and
“three-event corroborated candidate”; these describe evidence, not malicious intent.

## Reproduce

```powershell
.\.venv\Scripts\python.exe scripts/check_stack.py
.\.venv\Scripts\python.exe scripts/run_correlation.py
# Optional: use another default while still testing 60/300/900 seconds
.\.venv\Scripts\python.exe scripts/run_correlation.py --window 300
```

The runner always replays individual detection, checks frozen definitions/counts, fetches all inputs,
executes/repeats both EQL views for each window and validates the ES|QL census. A failed
or interrupted attempt marks its results unvalidated; rerun after resolving the cause.
No preprocessing, ingestion or mapping extension is needed. See the
[validation runbook](../docs/event-correlation-validation.md), [report](../analysis/correlation/correlation-report.md)
and [full results](../analysis/correlation/correlation-results.json) for hashes, exact IDs,
source provenance, gaps, exclusions and language differences.

Elastic references (checked 13 September 2026 UTC): [EQL search](https://www.elastic.co/docs/reference/query-languages/eql),
[sequence semantics](https://www.elastic.co/docs/reference/query-languages/eql/eql-syntax),
[request API](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-eql-search).
