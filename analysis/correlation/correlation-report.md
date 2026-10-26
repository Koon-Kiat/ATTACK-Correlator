# Historical event correlation results

Live validation passed: 2026-09-16T12:50:21.306930+00:00. Elasticsearch corpus: 102,011 events; 90,601 timed, 11,410 undated.

## Relationship and matching units

Primary: a Sysmon 1 cmd.exe from services.exe, with PowerShell in its command, followed by a separate refined PowerShell process event. Require exact host equality, shell actor GUID = child parent GUID (case-only normalization), explicit UTC time, strict ordering and an inclusive upper time bound.

Individual detections count distinct event.id. Correlation counts ordered tuples of distinct event IDs. Correlation IDs hash the compact UTF-8 JSON array of ordered IDs with SHA-256. They identify repeatable evidence, not maliciousness.

Broad comparison retains cmd.exe → PowerShell lineage with the same structural conditions, without requiring refined endpoint behaviour.

## Window sensitivity and participation

| Window | Broad tuples | Shell / PowerShell / total unique events | Broad hosts | Refined tuples | Shell / PowerShell / total unique events | Refined hosts | Removed tuples |
|---|---:|---|---:|---:|---|---:|---:|
| 60s | 261 | 222 / 261 / 483 | 3 | 3 | 3 / 3 / 6 | 3 | 258 |
| 300s | 261 | 222 / 261 / 483 | 3 | 3 | 3 / 3 / 6 | 3 | 258 |
| 900s | 261 | 222 / 261 / 483 | 3 | 3 | 3 / 3 / 6 | 3 | 258 |

The observed corpus is insensitive across the tested windows. This does not establish an optimal production window.

Default: **60s**. It captures all 3 service-origin lineage tuples found without a time cutoff. The exact validator uses `0 < gap_ns <= window × 10^9`.

### Fan-out

| Window / cohort | Maximum tuples per shell | Shells in multiple tuples | PowerShell events in multiple tuples | Total event participations |
|---|---:|---:|---:|---:|
| 60s / broad | 3 | 20 | 0 | 522 |
| 60s / refined | 1 | 0 | 0 | 6 |
| 300s / broad | 3 | 20 | 0 | 522 |
| 300s / refined | 1 | 0 | 0 | 6 |
| 900s / broad | 3 | 20 | 0 | 522 |
| 900s / refined | 1 | 0 | 0 | 6 |

JSON retains each fan-out event ID and multiplicity; duplicate source IDs fail verification and duplicate tuples are suppressed before accounting.

## Refined ordered tuples

| Correlation ID | Shell event → PowerShell event | Host | UTC times | Gap ns |
|---|---|---|---|---:|
| `4ea5eff5221ba4eca6dc410f2936bc0fbdae57394988bb6b10b746a41299324f` | `3154fbb47b3c3efd78fe60f5d197b960a91a267fc38c8db272196e38c200c358` → `e46b3e7a7b6f86a51ec757effeaf49ae2ce8438f9223cad86ed6a00f5d7e4aea` | DESKTOP-QGB4EQH | 2024-11-25T23:07:50.027718700Z → 2024-11-25T23:07:50.032974300Z | 5255600 |
| `e98dd94d6fc1cbf72c78924baf971a4f862ae4e20add2d79e15d32b1f53f9692` | `8f0564e44cea0da1038e46484c816a8668ee890529fcc83432f6c830a64d3e90` → `3faf8b4d35dd5fcb924ed44ed7e10d944f2b84243f9bf6f98c07b4e4b4d8d00d` | DESKTOP-FMI6MML | 2024-11-09T19:19:38.522452Z → 2024-11-09T19:19:38.535734500Z | 13282500 |
| `05a153adb26a4732128aeb009468ad5d3ff9997bf4155898051a7b93b16d50d3` | `c5a93a534cf031f5789b321d070b3f6cf33ec3e79e50b72cf15e384b7821e8e4` → `c87894aacb7c79e770e4eb8b1fd95fcf9612bb5fddba0c3f00edea3a9a9d6634` | DESKTOP-DS4FBF4 | 2024-11-06T09:58:51.235401Z → 2024-11-06T09:58:51.250364500Z | 14963500 |

Full original and normalized GUIDs, commands, users, provenance and exact timestamps are in [correlation-results.json](correlation-results.json). Raw preserved strings are displayed/reviewed only; no dataset command is executed.

## Broad sequences removed by refinement

Candidate sequence volume changes from **261 to 3** at the default window. This is not a measured false-positive reduction. Requiring the service-origin branch excludes other legitimate and suspicious shell ancestry. Refined PowerShell arguments exclude some valid interpreter use.

| Ordered IDs | Exclusion reasons | Shell / child command excerpts |
|---|---|---|
| `01ea2e887c88adf9d4b6a5edf353af461617e8372ebfe98f63b117460e79b760` → `32be01ebebaa05d0b83cb068bbcab36b41c24a1a48ca750d33bed090f68bb51a` | shell_not_in_phase6_service_origin_branch, powershell_not_in_phase6_refined_set | \"C:\\Windows\\system32\\cmd.exe\" /c start powershell -encodedCommand YwBtAGQAIAAvAGMAIAAiAFAAYQB0AGgAVABvAEEAdABvAG0AaQBjAHMARgBvAGwAZABlAHIAXAAuAC4AXABFAHgAdABlAHIAbgBhAGwAUABhAHkAbABvAGEAZABzAFwAdABvAHIAXAB / powershell  -encodedCommand YwBtAGQAIAAvAGMAIAAiAFAAYQB0AGgAVABvAEEAdABvAG0AaQBjAHMARgBvAGwAZABlAHIAXAAuAC4AXABFAHgAdABlAHIAbgBhAGwAUABhAHkAbABvAGEAZABzAFwAdABvAHIAXABUAG8AcgBcAHQAbwByAC4AZQB4AGUAIgA= -inputFor |
| `02f61bfd90fb07ebe9d617a930fff23bc06996115d3b7c575811a19b81ea49f7` → `3f17482439b937ce1b652c47e78e9542a934318bcf2afe599ae49951b7c170b3` | shell_not_in_phase6_service_origin_branch, powershell_not_in_phase6_refined_set | \"C:\\Windows\\system32\\cmd.exe\" /c start powershell -encodedCommand YwBtAGQAIAAvAGMAIAAiAFAAYQB0AGgAVABvAEEAdABvAG0AaQBjAHMARgBvAGwAZABlAHIAXAAuAC4AXABFAHgAdABlAHIAbgBhAGwAUABhAHkAbABvAGEAZABzAFwAdABvAHIAXAB / powershell  -encodedCommand YwBtAGQAIAAvAGMAIAAiAFAAYQB0AGgAVABvAEEAdABvAG0AaQBjAHMARgBvAGwAZABlAHIAXAAuAC4AXABFAHgAdABlAHIAbgBhAGwAUABhAHkAbABvAGEAZABzAFwAdABvAHIAXABUAG8AcgBcAHQAbwByAC4AZQB4AGUAIgA= -inputFor |
| `03823631fd9eb4d213224dee883ca219a7452060d8003e634e0c5c7eabd06d4e` → `f33be9eb24ac060a9c43dd7f856f0ab967d1d86b8ba4fe2aca2ec8501c8e4c9a` | shell_not_in_phase6_service_origin_branch, powershell_not_in_phase6_refined_set | cmd.exe /C powershell -exec bypass -e SQBuAHYAbwBrAGUALQBXAG0AaQBNAGUAdABoAG8AZAAgAC0AUABhAHQAaAAgAHcAaQBuADMAMgBfAHAAcgBvAGMAZQBzAHMAIAAtAE4AYQBtAGUAIABjAHIAZQBhAHQAZQAgAC0AQQByAGcAdQBtAGUAbgB0AEwAaQBzAHQAIABu / powershell  -exec bypass -e SQBuAHYAbwBrAGUALQBXAG0AaQBNAGUAdABoAG8AZAAgAC0AUABhAHQAaAAgAHcAaQBuADMAMgBfAHAAcgBvAGMAZQBzAHMAIAAtAE4AYQBtAGUAIABjAHIAZQBhAHQAZQAgAC0AQQByAGcAdQBtAGUAbgB0AEwAaQBzAHQAIABuAG8AdABlAH |

## Service installation corroboration

7045 records observe installation. Their preserved original imagePath is retrieved from `_source`, never queried as an indexed field. Compare the full command after trimming outer whitespace, case folding and collapsing repeated backslashes. Require same host, installation < shell < PowerShell and a total span within the tested window, followed by the exact GUID pair. No host/time-only fallback is permitted.

Previously observed relationships: **3 of 3** validate at the default window. **3** also satisfy both current refined endpoints.

| Ordered installation → shell → PowerShell IDs | Host | Gaps ns | Refined endpoints | Exclusion reasons |
|---|---|---|---|---|
| `0213192542e4d0897f86e0572722fb228d413a313b3347a86eb62d6316e3a21f` → `8f0564e44cea0da1038e46484c816a8668ee890529fcc83432f6c830a64d3e90` → `3faf8b4d35dd5fcb924ed44ed7e10d944f2b84243f9bf6f98c07b4e4b4d8d00d` | DESKTOP-FMI6MML | [21537200, 13282500] | True | None |
| `a92fd759d8b04d9161da5913fd5d56098415fad9f482fc94a1b4ff392f76232a` → `3154fbb47b3c3efd78fe60f5d197b960a91a267fc38c8db272196e38c200c358` → `e46b3e7a7b6f86a51ec757effeaf49ae2ce8438f9223cad86ed6a00f5d7e4aea` | DESKTOP-QGB4EQH | [15293400, 5255600] | True | None |
| `be75d1504e5784527dfd60bc35420d21f910b57ffba3ffcc1d84ec30c23070f9` → `c5a93a534cf031f5789b321d070b3f6cf33ec3e79e50b72cf15e384b7821e8e4` → `c87894aacb7c79e770e4eb8b1fd95fcf9612bb5fddba0c3f00edea3a9a9d6634` | DESKTOP-DS4FBF4 | [26838400, 14963500] | True | None |

The three-record association adds independent installation and process observations. It does not establish service survival, successful persistence, command completion, file creation or malicious intent. Marker-file service tests and authorized administration remain plausible.

## Missing support and FP/FN candidates

| Standalone refined set / excluded support | Distinct event count |
|---|---:|
| service_origin_shell_without_refined_child | 0 |
| refined_powershell_without_service_origin_shell_tuple | 287 |
| refined_shell_in_other_service_control_branch | 169 |

These counts describe absent support for this particular rule; they are not confirmed false negatives. Powershell without cmd ancestry, direct service executables, other interpreters, missing events/GUIDs/timestamps and delays can all evade a mandatory pair. Keep individual detections available.

Routine/ambiguous standalone comparisons retained from individual detection:

- `4ea94313bd0565c1a29ba059663e5824ebe4f2b9a7e25e1430f451017feef75c`: `powershell.exe -ExecutionPolicy Bypass -C \"$owners = @{};gwmi win32_process \|%% {$owners[$_.handle] = $_.getowner().user};$ps = get-process \| select processname,Id,@{l=\\\"Owner\\\";e={$owners[$_.id.tostring()]}};foreac`; parent `splunkd.exe`. Routine command semantics do not certify benign ancestry or authorization.
- `013759f2600917245402d8f22e97bde725d1262bdd8b0a6ec1ba03f28de52002`: `c:\\windows\\system32\\cmd.exe  /c cd /d C:\\Users\\mari\\AppData\\Local\\Temp\\`; parent `cmd.exe`. Routine command semantics do not certify benign ancestry or authorization.

## Query languages and live verification

EQL is an executable sequence view with the same endpoint command patterns. Its runtime fields are defined in [eql-request.json](../../correlation/eql-request.json) for the request only; the index mapping is unchanged. Because EQL requires a date rather than date_nanos, it uses millisecond time plus a nanosecond tiebreaker and a one-millisecond maxspan envelope. Python checks strict ordering and the exact inclusive window from preserved UTC timestamps.

Both EQL endpoint predicates were independently executed over the historical corpus and their complete event-ID sets compared with individual detection: 3 service-origin shells and 290 refined PowerShell events. The query predicates agree on all retained endpoints.

EQL maintains one pending sequence per join key/state, so it is not generally an all-pairs join. The deterministic validator enumerates full individual detection sets and reports any EQL omissions; it never uses a capped EQL response as the denominator.

Broad EQL returns 222 sequences; complete enumeration retains 261 tuples. 20 shells have multiple children (maximum 3). EQL omits 39 valid broad pairings. Refined EQL returns 3 exact accepted tuples. Fan-out examples and all omitted IDs are retained in JSON.

| Window / EQL view | Raw sequences | Exact accepted | Not returned by EQL | Replayed |
|---|---:|---:|---:|---|
| 60s / broad | 222 | 222 | 39 | True |
| 60s / refined | 3 | 3 | 0 | True |
| 300s / broad | 222 | 222 | 39 | True |
| 300s / refined | 3 | 3 | 0 | True |
| 900s / broad | 222 | 222 | 39 | True |
| 900s / refined | 3 | 3 | 0 | True |

### correlation.eql

```eql
sequence by host.name with maxspan=60001ms
  [any where event.provider == "Microsoft-Windows-Sysmon" and event.code == "1"
    and correlation.name_lc == "cmd.exe"
    and correlation.parent_name_lc == "services.exe"
    and correlation.command_lc regex ".*(powershell[.]exe|pwsh[.]exe).*"
  ] by correlation.actor_guid
  [any where event.provider == "Microsoft-Windows-Sysmon" and event.code == "1"
    and correlation.name_lc in ("powershell.exe", "pwsh.exe")
    and (
      (correlation.command_lc regex ".*(invoke-webrequest|downloadstring|downloadfile|[^a-z0-9_]iwr[^a-z0-9_]).*"
        and correlation.command_lc regex ".*(invoke-expression|[^a-z0-9_]iex[^a-z0-9_]|start-process).*")
      or
      (correlation.command_lc regex ".*[ ]-(w|windowstyle)[ ]+hidden([ ].*)?"
        and correlation.command_lc regex ".*[ ]-(nop|noprofile)([ ].*)?"
        and correlation.command_lc regex ".*[ ]-(c|command)[ ]+.*")
    )
  ] by correlation.parent_guid
```

### baseline.eql

```eql
sequence by host.name with maxspan=60001ms
  [any where event.provider == "Microsoft-Windows-Sysmon" and event.code == "1"
    and correlation.name_lc == "cmd.exe"
  ] by correlation.actor_guid
  [any where event.provider == "Microsoft-Windows-Sysmon" and event.code == "1"
    and correlation.name_lc in ("powershell.exe", "pwsh.exe")
  ] by correlation.parent_guid
```

### correlation.esql

```esql
FROM windows-apt-events-*
| WHERE event.provider == "Microsoft-Windows-Sysmon" AND event.code == "1"
    AND TO_LOWER(process.name) IN ("cmd.exe", "powershell.exe", "pwsh.exe")
| EVAL endpoint = TO_LOWER(process.name),
    service_origin = TO_LOWER(COALESCE(process.parent.name, "")) == "services.exe"
        AND TO_LOWER(COALESCE(process.command_line, "")) RLIKE ".*(powershell[.]exe|pwsh[.]exe).*"
        AND TO_LOWER(process.name) == "cmd.exe"
| STATS raw_events = COUNT(*), timed_events = COUNT(@timestamp),
    actor_guid_events = COUNT(process.entity_id), parent_guid_events = COUNT(process.parent.entity_id)
    BY endpoint, service_origin
| SORT endpoint ASC, service_origin ASC
| LIMIT 10
```

ES|QL supplies an endpoint coverage census, not a temporal join:

```json
[
  {
    "raw_events": 7714,
    "timed_events": 7714,
    "actor_guid_events": 7714,
    "parent_guid_events": 7703,
    "endpoint": "cmd.exe",
    "service_origin": false
  },
  {
    "raw_events": 3,
    "timed_events": 3,
    "actor_guid_events": 3,
    "parent_guid_events": 3,
    "endpoint": "cmd.exe",
    "service_origin": true
  },
  {
    "raw_events": 2060,
    "timed_events": 2060,
    "actor_guid_events": 2060,
    "parent_guid_events": 2021,
    "endpoint": "powershell.exe",
    "service_origin": false
  }
]
```

All 10,151 input IDs were fetched in bounded batches and checked against current source telemetry. individual detection was replayed first. Query, request, prerequisite and mapping hashes are recorded in the JSON.

## Limitations and reproduction

- Strong structure is exact host equality, GUID case-only comparison, strict order and bounded nanosecond time; intent remains unknown.
- EQL uses request-local date milliseconds plus a nanosecond tiebreaker, with a one-millisecond maxspan envelope. Python enforces 0 < gap <= window exactly.
- EQL has one pending sequence per join key/state; Python enumerates every eligible tuple and reports any EQL omissions. Equal live counts do not prove universal equivalence.
- Service imagePath is retrieved original evidence only. Full-command case/backslash comparison is lexical association, not Windows command parsing or service API identity.
- No persistence, service survival, successful command/file outcome or malicious intent is established.
- Missing events, GUIDs or explicit UTC times, renamed/hosted interpreters, other parents/interpreters, direct executables and delays beyond the window can remove support.
- individual detection refinements exclude valid technique activity; fewer tuples are not measured FP/FN rates. Precision, recall, F1 and FPR remain unavailable.
- Authorized marker-file tests, administration and service wrappers remain plausible explanations for correlated candidates.

```powershell
.\.venv\Scripts\python.exe scripts/run_correlation.py
.\.venv\Scripts\python.exe scripts/run_correlation.py --window 300
```

The default command always evaluates 60, 300 and 900 seconds. A custom window is added to those checks. See [delivery record](../../docs/event-correlation-validation.md) for tests, scope and related completed workflows.

Elastic references checked 2026-09-13 UTC:

- [Elastic reference 1](https://www.elastic.co/docs/reference/query-languages/eql)
- [Elastic reference 2](https://www.elastic.co/docs/reference/query-languages/eql/eql-syntax)
- [Elastic reference 3](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-eql-search)
- [Elastic reference 4](https://www.elastic.co/docs/manage-data/data-store/mapping/define-runtime-fields-in-search-request)
