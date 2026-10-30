# Event correlation runbook

Use the [correlation methodology](correlation.md) for interpretation and the
[query reference](../correlation/README.md) for endpoint predicates, runtime fields,
nanosecond boundaries, tuple identities and service-object comparison semantics.

## Reproduce and verify

Complete the [individual detection prerequisites](individual-detection-implementation.md#reproduce)
first. With the source index and local stack available, run from the project root:

```powershell
.\.venv\Scripts\python.exe scripts/check_stack.py
.\.venv\Scripts\python.exe scripts/run_correlation.py
# Optional default window; the required 60/300/900-second checks still run:
.\.venv\Scripts\python.exe scripts/run_correlation.py --window 300
```

Use `.venv/bin/python` on Bash. Each run replays individual detections, checks frozen
query/count contracts and retrieves all 10,151 correlation input IDs. It compares
the ES|QL endpoint census, repeats the EQL views, enumerates every host/GUID/time pair
and validates installation evidence fetched from original `_source` fields.
Mapping/count continuity, partial responses and export caps are checked explicitly.

The runner writes the [results JSON](../analysis/correlation/correlation-results.json)
and [report](../analysis/correlation/correlation-report.md), including query hashes,
source IDs, provenance, time gaps and excluded examples. An interrupted run invalidates
previous success output; resolve the cause and rerun. No source-index writes or mapping
extensions are required.

## Expected evidence units

| Observation | Saved result at 60 / 300 / 900 seconds |
|---|---|
| Complete broad ordered pairs | 261 / 261 / 261; 483 participating events |
| Complete refined ordered pairs | 3 / 3 / 3; 6 participating events |
| Broad EQL sequences | 222 per window; 39 fan-out pairs omitted by sequence semantics |
| Refined EQL sequences | All three exact refined pairs |
| Separately corroborated service triples | Three per window; nine events on three hosts |

These are candidate evidence units, not attacks or measured error rates. The complete
Python enumeration is authoritative for pair counts. All three known service triples
satisfy refined endpoints; no excluded triple is invented. The
[excluded examples in the report](../analysis/correlation/correlation-report.md) document
real broad lineage outside both refined endpoint predicates.

## Software checks and downstream review

```powershell
.\.venv\Scripts\python.exe -m pytest -q --basetemp .test-tmp
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m pip check
```

Tests exercise exact host/GUID matching, strict ordering, inclusive nanosecond windows,
fan-out, duplicate identities, metadata independence, source-only service association
and partial/capped responses. Recorded historical test totals are not a substitute
for running the current suite. Continue with [scenario evaluation](evaluation.md).
