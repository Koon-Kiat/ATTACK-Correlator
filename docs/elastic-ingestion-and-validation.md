# Elastic ingestion and validation

This engineering record preserves the observations and checks for this workflow.
For the completed implementation and current status, see the [project README](../README.md).

Completed 2026-09-12. Elasticsearch, Kibana and Logstash **9.5.3** are operational.
All **102,011** verified processed events are indexed in `windows-apt-events-v1`.
Final technique selection, detections, correlation and dashboards remain later work.

## Run the workflow

Start Docker Desktop in Linux-container mode, then run from the project root:

```powershell
docker compose up -d --wait --wait-timeout 360
.\scripts\ingest.ps1
.\.venv\Scripts\python.exe scripts/validate_ingestion.py
```

Linux/macOS equivalents are `bash scripts/ingest.sh` and
`.venv/bin/python scripts/validate_ingestion.py`. The PowerShell wrapper was exercised
end to end on Windows; the Bash wrapper delegates to the same Python entry point and
was syntax-checked, but a separate Linux host run was not performed.

The ingestion command checks Elasticsearch reachability, runs the existing full data normalization
verifier, installs the template, creates an absent target index, enables the finite file
input, waits for all events to drain, refreshes and runs live validation. The verifier
checks all raw/processed/report/code hashes and reconstructs every original source row.
No preprocessing was rerun and no raw or processed evidence was modified for ingestion validation.

Normal reruns retain the index and overwrite documents using the existing `event.id`
as Elasticsearch `_id`. A completed replay began and ended with **102,011** documents.
`-Reset` / `--reset` deliberately deletes only this exact target index before recreation;
the option is unnecessary for ordinary runs. `-TimeoutSeconds` / `--timeout` changes
the default 1,200-second wait limit. Interrupted runs retain their evidence and observations.

## Index and Logstash design

The generated [template](../elasticsearch/templates/windows-apt-events-template.json)
is installed as `windows-apt-events-template`, with pattern `windows-apt-events-*`,
priority 200, one primary shard and zero replicas. Its mappings exactly match the
verified data normalization contract: `dynamic: strict`, `date_nanos`, explicit ECS types and
disabled parsing for original evidence payloads. Live mapping equality was verified.
Elasticsearch adds its own template creation/modification dates and canonicalizes
settings to `index.*`; validation compares the substantive contract.

The target is a **normal index**, allowing valid undated events. A data stream would
require an event timestamp. Later queries should use `windows-apt-events-*`.

`logstash/pipeline/windows-apt.conf` reads one UTF-8 NDJSON line at a time through a
read-only mount of `dataset/processed/`; no dataset is copied into an image. A small
Ruby filter creates the event from the processed payload, discarding file-input/runtime
decorations. It verifies the existing deterministic ID and timestamp-quality relationship.
Nested ECS fields, provenance, original source strings and source metadata survive.
Output uses the existing credential environment, verified local CA and static index name.
No credentials were added to source or reports.

Ordinary Compose startup defaults to an inactive input path. The wrapper enables the
verified file for a run. `mode => read` processes EOF as completion, while
`exit_after_read => false` leaves the service available. `/dev/null` sincedb means a
container restart replays the enabled file; stable IDs prevent duplicate inflation.
This deliberately small project workflow is not a production checkpoint system.

## Timestamp and evidence results

| Validation | Expected | Live result |
|---|---:|---:|
| Processed/indexed events | 102,011 | 102,011 |
| Rejected by input guard or Elasticsearch | 0 | 0 |
| Explicit UTC / existing @timestamp | 90,601 | 90,601 |
| Unresolved / absent @timestamp | 11,410 | 11,410 |
| Unresolved events with an invented timestamp | 0 | 0 |
| Searchable ECS field coverages | 38 | All 38 match data normalization |
| Source ATT&CK annotation coverage | 63,619 | 63,619 |
| Scenario context coverage | 102,011 | 102,011 |
| Assigned scenario IDs | 96,106 | 96,106 |
| Unresolved scenario attribution | 5,905 | 5,905 |
| Representative telemetry queries | 11 | All return evidence |
| Source comparison categories | 13 | All pass, across 8 distinct records |

The source has no justified timezone/date conversion for the 11,410 unresolved events.
Logstash explicitly removes its generated `@timestamp` from them. These events remain
searchable without a time filter; they cannot participate in timestamp-based correlation.

Valid instants retain nanoseconds. One sampled timestamp is serialized as
`2024-12-06T18:26:09.273988400Z` instead of `2024-12-06T18:26:09.2739884Z`: only
insignificant trailing zeros differ. All other sampled values and all original evidence
namespaces match exactly. Indexed **date_nanos doc values**, as well as `_source`,
were checked, so source retention alone is not mistaken for indexed precision.

The observed event range is approximately **2024-10-29 through 2024-12-22 UTC**,
despite the distribution's 2025 name. Date aggregations report millisecond boundaries;
nanosecond spot checks use doc values. No dates were shifted to the current day.

## Search and source checks

The [generated report](../analysis/ingestion/ingestion-report.md) includes working query
examples and exact counts. The [JSON evidence](../analysis/ingestion/ingestion-validation.json)
contains the executed Query DSL, KQL equivalents, mapping checks, field coverage,
source filenames/rows/IDs and timestamp comparisons. These are search probes, not
installed detection rules. ATT&CK annotations and scenario attribution remain metadata.

In Kibana Dev Tools, an example is:

```http
GET windows-apt-events-*/_search
{
  "size": 5,
  "query": {
    "bool": {
      "filter": [
        {"term": {"event.provider": "Microsoft-Windows-Sysmon"}},
        {"term": {"event.code": "1"}},
        {"exists": {"field": "process.command_line"}}
      ]
    }
  }
}
```

For undated evidence:

```http
GET windows-apt-events-*/_count
{
  "query": {
    "bool": {
      "filter": [{"term": {"windows_apt.quality.timestamp": "unresolved"}}],
      "must_not": [{"exists": {"field": "@timestamp"}}]
    }
  }
}
```

The full query suite covers process creation, command lines, parent/child GUIDs, files,
registry, network endpoints, DNS, source annotations, scenario context and both time
states. Source selection takes the first matching NDJSON record for each category,
also including original messages, high-precision timestamps and normalization warnings.
It compares entire objects, with only insignificant timestamp spelling normalized.
`event.original` and disabled payloads intentionally have no searchable index; their
exact values are verified through representative `_source` retrieval.

## Failure handling and operational observations

Malformed JSON, missing/invalid IDs and contradictory timestamp states retain the
complete input plus reason in
`/usr/share/logstash/data/rejected-<run_id>.ndjson` inside the Logstash data volume.
Elasticsearch mapping failures use its built-in DLQ under
`/usr/share/logstash/data/dead_letter_queue/main`. These files are never replayed or
deleted automatically. Inspect them and the service logs after a failed run. An empty
DLQ has a one-byte segment header; it is not a rejected document.

Final successful run metrics show 102,011 input/output events and 102,011 successful
Elasticsearch operations, with zero input rejections, non-retryable failures, expired
or dropped DLQ events. Both metadata coverage and full document counts match expectations.
Run observations, including unsuccessful development validations, are retained in
`analysis/ingestion/runs/`; `latest-run.json` identifies the completed workflow.

The final full replay took **69.83 seconds**, measured from container recreation through
pipeline drain. Verification and post-ingestion queries are outside that interval.
The validation snapshot recorded **1,378,177,460 bytes (about 1.38 GB)** of index storage.
Storage changes as replayed Lucene segments merge. These are observations from one
local machine, not benchmarks.

Two implementation issues were found and corrected during live testing:

- `exit_after_read => true` ended Logstash and triggered Compose restart/replay. Keeping
  the read input alive fixed service availability; stable IDs prevented count inflation.
- Initial validation confused scenario context coverage with assigned scenario IDs.
  The source has 5,905 unresolved assignments. Validation now checks context, assigned
  IDs and every attribution strength separately against data normalization.

Authenticated Kibana status is used to obtain its version; the unauthenticated endpoint
only provides limited status. No data normalization defect or source modification was required.

## Tests and deliverables

**89 Python tests passed** (76 previous + 13 ingestion validation), covering the data normalization guard,
template installation/conflicts, exact count failures, duplicate inflation, deterministic
ID use in source retrieval, unresolved time handling and nanosecond comparisons.
**Five native Logstash Ruby tests passed**, covering nested evidence, IDs, nanoseconds,
missing time, malformed JSON and contradictory timestamps. Logstash configuration
validation passed. Ruff lint/format and `pip check` passed. Live ingestion and an
independent full data normalization plus Elasticsearch validation also passed.

Created `scripts/ingest.py`, `elastic_local.py`, `validate_ingestion.py`,
`logstash/scripts/preserve_event.rb`, the event template, `tests/test_ingestion.py`,
the two generated ingestion validation reports and this record. Updated both ingestion wrappers,
Compose mounts/environment, Logstash pipeline/settings, README, architecture,
limitations and template notes. Raw/processed evidence remains ignored and unchanged.

technique selection should review the indexed behavioural evidence and dataset inspection candidate inventory,
then select exactly three defensible ATT&CK sub-techniques with observable conditions
and a documented validation basis. See [ATT&CK sub-technique selection](attack-subtechnique-selection.md) for the completed subsequent workflow.

## References

- [Elastic file input semantics](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-file)
- [Logstash Ruby filter and native tests](https://www.elastic.co/docs/reference/logstash/plugins/plugins-filters-ruby)
- [Elasticsearch output IDs, TLS and failure handling](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-elasticsearch)
- [Built-in Logstash dead-letter queues](https://www.elastic.co/docs/reference/logstash/dead-letter-queues)
- [Elasticsearch date_nanos](https://www.elastic.co/docs/reference/elasticsearch/mapping-reference/date_nanos)
