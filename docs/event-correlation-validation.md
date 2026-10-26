# Event correlation validation

This engineering record preserves the observations and checks for this workflow.
For the completed implementation and current status, see the [project README](../README.md).

Date: 13 September 2026, Singapore. Scope: historical event correlation and evidence
validation for the existing three ATT&CK strategies. Data, mappings, technique selection
and working individual detection designs remain unchanged. This record covers the correlation component; the dashboard and scenario review have separate records. Incident reconstruction, attack generation and automated response remain outside scope.

## Implemented relationship

The primary correlation requires a refined service-origin cmd.exe event followed by a
separate refined PowerShell event. Join on exact `host.name` and shell
`process.entity_id` = child `process.parent.entity_id`, with GUID case normalized only
for comparison. Require explicit valid UTC timestamps and **0 < gap <= window**, with
nanosecond precision and an inclusive upper boundary. Host/time alone is insufficient.

The individual unit is distinct event.id. The correlation unit is an ordered tuple of
distinct event IDs, identified reproducibly by SHA-256 of the compact UTF-8 JSON array.
The validator rejects duplicate source IDs, retains all eligible pairings and suppresses
duplicate tuples. It reports participating events and fan-out separately from tuple count.

## Live results

| Window | Broad cmd → PowerShell tuples | Refined tuples | Broad events / hosts | Refined events / hosts |
|---|---:|---:|---|---|
| 60 seconds | 261 | 3 | 483 / 3 | 6 / 3 |
| 300 seconds | 261 | 3 | 483 / 3 | 6 / 3 |
| 900 seconds | 261 | 3 | 483 / 3 | 6 / 3 |

Broad participation is **222 shells and 261 PowerShell events**. Twenty shells fan out
(maximum three children); total pair participations are 522 across 483 unique events.
The refined tuples use three shells and three children, with no fan-out. Candidate tuple
volume falls by 258 (261 → 3), not a measured false-positive reduction.

All three service-origin GUID relationships found without a time cutoff fit within
60 seconds. This supports the default on this corpus; unchanged 60/300/900 counts do
not establish an optimal production window.

The corpus remains **102,011 events / 90,601 timed / 11,410 undated**. individual detection replays retain
290 PowerShell, 172 shell, 41 service-create and 108 service-config refined candidates.
Only three shell candidates belong to the required service-origin branch. Thirty-nine
baseline PowerShell events lack a usable parent GUID; no ordered join invents missing keys
or event times.

## Executable query and validator roles

- `correlation/correlation.eql`: refined two-event sequence with the individual detection endpoint
  command patterns and strong host/GUID keys.
- `correlation/baseline.eql`: broad lineage sequence view.
- `correlation/eql-request.json`: complete executable default request, supplying temporary
  lowercase name/command/GUID fields, millisecond date and nanosecond tiebreaker.
- `correlation/correlation.esql`: endpoint census with exact raw counts and timestamp/GUID
  coverage; it does not attempt a temporal join.
- `scripts/run_correlation.py`: authoritative individual detection replay, complete source readback,
  exact nanosecond pairing, all-tuple enumeration, EQL comparison and service-object review.

Elastic's EQL timestamp accepts date, not date_nanos. The search therefore uses a
request-local millisecond date and a one-millisecond maxspan envelope (60001ms for a
60-second evaluation). The original date_nanos mapping stays unchanged. Python checks
strict ordering and the exact inclusive window from preserved UTC timestamps.

Both EQL endpoints are independently executed and compared with the complete individual detection
sets (3 service-origin shells and 290 refined PowerShell events). EQL's sequence engine
has one pending sequence per join key/state: the broad view returns **222** sequences,
omitting **39** valid fan-out pairings retained by the **261-tuple** complete join. The
refined EQL view returns all **3** exact tuples. These differences are explicit in the
report; EQL output is never used as an exhaustive denominator without verification.

## Three-technique supporting evidence

All **3 of 3** previously observed SCM 7045 → services-origin cmd → PowerShell relationships
validate, involving **9 distinct records on 3 hosts**. All three also satisfy current
individual detection refined shell/PowerShell predicates. **None is excluded by the current refinement.**

The separate source-evidence path retrieves the unindexed original SCM imagePath, compares
it to the full shell command with documented Windows case/backslash normalization, then
checks exact ancestry, strict installation < shell < PowerShell ordering and the total
span. It does not query disabled original fields or change mappings.

| Host | Shell → child gap ns | Installation → shell gap ns | All refined endpoints |
|---|---:|---:|---|
| DESKTOP-QGB4EQH | 5,255,600 | 15,293,400 | Yes |
| DESKTOP-FMI6MML | 13,282,500 | 21,537,200 | Yes |
| DESKTOP-DS4FBF4 | 14,963,500 | 26,838,400 | Yes |

Exact IDs, timestamps, original/normalized join values and source provenance are retained
in [results JSON](../analysis/correlation/correlation-results.json) and the
[generated report](../analysis/correlation/correlation-report.md). A representative fan-out
shell and all its children are also retained. Service installation, independently observed
execution and a separate child strengthen structural evidence. They do not establish
maliciousness, service survival, persistence, command success or requested file creation.
The marker-file commands can represent authorized service tests.

## FP/FN and evaluation preparation

The broad removed example beginning `01ea2e88…` has a GUID-linked encoded-only PowerShell
child (`32be01eb…`), outside both the service-origin branch and the refined child argument
conditions. Full IDs and strings are retained. This illustrates a technique-consistent
relationship omitted by the refinement, not an independently proven false negative.
No known service triple is artificially reported as excluded.

There are **287** refined PowerShell records without the required service-origin tuple
and **169** refined shell records in the other service-control branch. These remain
standalone candidates. Routine inventory/directory-changing comparisons retain their
ambiguous ancestry. Approved administration, service wrappers and lab marker tests can
match even with strong structural support.

Missing Sysmon events, actor/parent GUIDs or UTC timestamps, renamed/hosted PowerShell,
other parents/interpreters, direct service executables, unobserved service execution,
window-exceeding delays and deliberately narrow individual detection predicates all limit coverage.
Use standalone behavioural / strong structural correlation / three-event corroborated
candidate categories, keeping intent separate. No arbitrary score, confusion matrix,
precision, recall, F1 or FPR is supplied. See [evaluation](evaluation.md).

## Reproduce and verify

With the existing local stack running, from the repository root:

```powershell
.\.venv\Scripts\python.exe scripts/check_stack.py
.\.venv\Scripts\python.exe scripts/run_correlation.py
.\.venv\Scripts\python.exe -m pytest -q --basetemp .test-tmp/correlation
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m pip check
```

Optional `--window 300` selects another default while retaining all three required
sensitivity windows. The runner always replays individual detection; it checks query hashes and count
contracts rather than silently updating expectations. It reads all **10,151 input IDs**
from Elasticsearch, compares the endpoint census, repeats each EQL sequence query, and
checks mapping/count continuity. No result is accepted at an export cap or after a partial
response. Interrupted validation invalidates prior results and can be resumed by rerunning.

The focused tests cover exact host/GUID matching, GUID case, strict and nanosecond order,
window boundaries, all three windows, missing data, duplicate source IDs/tuples, stable
IDs, fan-out, refined membership, metadata independence, source-only service normalization,
partial/capped EQL responses and exact EQL endpoint membership. Full test and live-check
results passed before the local commit: **180 pytest tests**, Ruff lint/format checks
and `pip check`. Live checks executed both EQL endpoints, both sequence views twice per
window, the ES|QL census twice and the complete validator. No remote push is performed.

## Artifacts and related review

New/updated work includes `correlation/`, `scripts/run_correlation.py`,
`scripts/correlation_report.py`, `tests/test_correlation.py`, `analysis/correlation/`,
this record, and the project README, correlation/evaluation/methodology/limitations and
architecture documentation. Existing individual detection validation outputs are refreshed by replay;
the detection query hashes and selected techniques remain unchanged.

Git attributes retain LF for new text artifacts. Explicit exceptions preserve older
hash-linked reports byte-for-byte, including their original CRLF and trailing blank
lines. Those narrow whitespace exceptions avoid altering immutable evidence merely to
clean its generated formatting. The initial commit retains source,
queries, tests, documentation and analysis reports; credentials, environments, datasets,
certificates, caches and runtime state remain ignored. No remote push is authorized.

The completed [scenario review](scenario-validation-and-evaluation.md) examines the three corroborated examples, removed encoded-only lineage and routine/ambiguous comparisons. Review units and uncertainty remain explicit; independent accuracy cannot be measured.
