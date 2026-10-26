# Scenario validation and evaluation

This engineering record preserves the observations and checks for this workflow.
For the completed implementation and current status, see the [project README](../README.md).

Scope: bounded evidence review and scenario demonstration using completed detections and
correlation. No detection redesign, dataset/mapping changes, attack execution, full incident
chronology, dashboard implementation or technical report.

## Prerequisites and primary scenario

The complete individual detection and event correlation replay retains **102,011 total / 90,601 timed / 11,410 undated events**.
Refined individual counts remain **290 PowerShell / 172 shell / 41 service-create / 108
service-config** observations. At 60/300/900 seconds, complete enumeration retains
**261 broad pairs / 3 refined pairs / 3 corroborated triples**. Broad EQL returns 222
sequences, omitting 39 fan-out pairings; it is not the complete denominator.

Selection: earliest verified triple by installation UTC nanoseconds, with ordered IDs
as the tie-breaker. All three are verified live before selection; drift fails validation
rather than silently replacing a scenario. Primary: **DESKTOP-DS4FBF4**, 6 November 2024.

| Role / technique | Exact event ID | UTC timestamp | Gap to next record |
|---|---|---|---:|
| SCM 7045 / T1543.003 | `be75d1504e5784527dfd60bc35420d21f910b57ffba3ffcc1d84ec30c23070f9` | 2024-11-06T09:58:51.208562600Z | 26,838,400 ns |
| Service-origin cmd.exe / T1059.003 | `c5a93a534cf031f5789b321d070b3f6cf33ec3e79e50b72cf15e384b7821e8e4` | 2024-11-06T09:58:51.235401Z | 14,963,500 ns |
| GUID-linked PowerShell / T1059.001 | `c87894aacb7c79e770e4eb8b1fd95fcf9612bb5fddba0c3f00edea3a9a9d6634` | 2024-11-06T09:58:51.250364500Z | End |

Total span: **41,801,900 ns**. Hosts match exactly. Preserved service imagePath is retrieved
from `_source` and compared to the full shell command using documented case, outer-whitespace
and backslash normalization. Shell actor GUID equals child parent GUID with case-only
comparison. Explicit times satisfy installation < shell < child within 60 seconds.

ARTService/LocalSystem installation is the **SCM baseline cohort**, not refined sc.exe
create/config. The shell meets the service-origin branch; PowerShell meets hidden + no
profile + inline command conditions. The marker-file request can represent authorized
testing; it does not prove file creation, persistence, service survival or malicious intent.
Both later triples on DESKTOP-FMI6MML and DESKTOP-QGB4EQH pass the same checks and refined
endpoints. None of the three known relationships is excluded.

## Review protocol and findings

The deterministic set has **11 units / 16 unique reviewed events**:

- One primary ordered triple: three-event corroborated candidate.
- Two remaining refined ordered pairs: strong structural correlation.
- First ordered excluded broad tuple: encoded-only child outside both the service-origin
  shell branch and refined PowerShell predicate.
- Lowest-ID standalone refined PowerShell and other-branch refined shell events.
- All five individual detection comparisons: inventory-style PowerShell, directory-changing shell,
  Defender-looking installation, Fax configuration and direct executable service creation.

Two additional installation records support corroboration, giving **18 scenario evidence
records**. Every unit records type, techniques, behaviour, structural category,
time/GUID/provenance completeness, inclusion/exclusion, plausible legitimate explanation,
uncertainty and coverage limits. Categories describe structure, not ground truth. The
review is illustrative, not a statistical sample of intent or error rates.

Both broad and refined pairs already require host/GUID/order/time. Adding service-origin
and refined child behaviour yields 261 → 3 candidate pairs; this is not measured FP reduction.
Authorized wrappers can still match. Missing events/GUIDs/times, alternate parents or
interpreters, renamed/hosted PowerShell, direct executables, delays and narrow command
predicates limit coverage. Keep **287 refined PowerShell** and **169 other-branch shell**
observations visible as standalone candidates. Exclusion is neither a benign verdict nor
a confirmed false negative. No accuracy metrics, confusion matrix or numeric scores.

## Artifacts and reproduction

- [Scenario JSON](../analysis/scenarios/scenario-demonstration.json) and
  [demonstration](../analysis/scenarios/scenario-demonstration.md): exact triples,
  telemetry, provenance, selection, technique/rule mapping and full review criteria.
- [Evaluation JSON](../analysis/evaluation/evaluation-results.json) and
  [report](../analysis/evaluation/evaluation-report.md): units/counts, FP/FN findings,
  uncertainty, input/output/query hashes and live checks.
- [Helper](../scripts/build_scenario_evidence.py) and [renderer](../scripts/scenario_report.py):
  reuse existing time/GUID/image association and source-verification functions.
- [Exact-ID ES\|QL](../analysis/scenarios/primary-scenario.esql) and
  [search request](../analysis/scenarios/primary-scenario-search.json): both executed live
  and compared with all three ordered records and evidence fields.
- [Dashboard contract](../analysis/evaluation/dashboard-contract.json) and
  [panel specification](dashboard.md): exact sources, metrics, filters, empty states and
  acceptance criteria. **611 verified activity rows** and per-rule daily UTC totals are
  prepared. No dashboard or source-index derived fields are installed.

```powershell
.\.venv\Scripts\python.exe scripts/build_scenario_evidence.py
.\.venv\Scripts\python.exe scripts/build_scenario_evidence.py --reuse-validated-prerequisites
.\.venv\Scripts\python.exe -m pytest -q --basetemp .test-tmp/evaluation
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m pip check
```

Default replay includes event correlation and its full individual detection validation. The explicit reuse option
requires saved hashes/counts to pass and still checks live counts, mapping and source
evidence. The helper verifies **621 source IDs**, all three triples, every reviewed unit,
all four complete refined activity cohorts and their host/time ranges. Starting a run
invalidates old success artifacts; failures cannot retain an apparently current evaluation.

Fixed prerequisite/source inputs produce byte-identical JSON/Markdown. A fresh replay
changes its audit timestamp and snapshot hashes, not scenario choice or evidence units.
Two consecutive reuse runs verify output byte equality. Tests cover selection/ties,
ordering, host/GUID/image failures, missing IDs/provenance, metadata independence,
comparison order, service cohort separation, exact queries, partial responses, units,
daily reconciliation, output escaping and artifact integrity.

Final checks: **213 pytest tests passed**, including **33 scenario/evaluation tests**;
Ruff lint passed, **41 Python files** passed formatting, and `pip check` reported no
broken requirements. The complete default live helper passed, followed by two live reuse
runs: all **seven generated files** were byte-identical. individual detection and event correlation counts and original
query/algorithm files remain unchanged apart from refreshed validation timestamps/hashes.

## Dashboard and Git scope

The completed [Kibana dashboard](kibana-dashboard-implementation.md) verifies exact denominators, historical filters, source links, empty states and saved-object export/import. Generated reports and code archives remain local under the ignored `reports/` directory. No malicious/benign or forced network panel is supported.

The local commit includes intended code/tests, documentation, reviewed artifacts and
prerequisite outputs refreshed by required replay. Original detection/correlation queries
and algorithms are unchanged. Credentials, datasets, environments, certificates, runtime
state, caches and archives are excluded. No remote push.
