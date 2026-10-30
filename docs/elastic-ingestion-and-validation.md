# Elastic ingestion and validation

The local pipeline loads verified processed telemetry into the ordinary
`windows-apt-events-v1` index. Elastic 9.5.3 is pinned in `.env.example`. Saved validation
records contain 102,011 events: 90,601 timed and 11,410 intentionally undated. Those
records describe their original runs; check the stack before assuming it is running.

## Run the workflow

Complete [dataset preparation](dataset.md) and [normalization](sanitization.md) first.
Start Docker Desktop in Linux-container mode, then run from the project root:

```powershell
docker compose up -d --wait --wait-timeout 360
.\scripts\ingest.ps1
.\.venv\Scripts\python.exe scripts/validate_ingestion.py
```

Linux/macOS equivalents are `bash scripts/ingest.sh` and
`.venv/bin/python scripts/validate_ingestion.py`. The Bash wrapper delegates to the
same Python entry point; the retained end-to-end host verification was on Windows.

The ingestion wrapper checks Elasticsearch, runs full raw/processed integrity and
row-conservation verification, installs the template, creates an absent index,
enables the NDJSON input, waits for drain, refreshes and validates the indexed data.
Normal reruns overwrite the same deterministic `event.id` values used as `_id`.
They do not delete the index or inflate the corpus with duplicate copies.

`-Reset` / `--reset` deletes only the target index before recreation; ordinary replay
does not need it. `-TimeoutSeconds` / `--timeout` changes the default 1,200-second wait.

After selection has been established, save independent ingestion rechecks separately:

```powershell
.\.venv\Scripts\python.exe scripts/validate_ingestion.py --output-directory analysis/detections/prerequisites
```

Selection checks the original ingestion report's hash. Re-ingestion or intentional
regeneration of that report requires rebuilding selection provenance using the
[detection runbook](individual-detection-implementation.md#reproduce).

## Index and Logstash contract

The [template](../elasticsearch/templates/windows-apt-events-template.json) wraps the
verified normalization mapping: strict fields, `date_nanos`, explicit ECS types and
disabled parsing of original evidence payloads. It uses priority 200, one shard and
zero replicas with pattern `windows-apt-events-*`. A conflicting existing mapping
stops ingestion. The ordinary index permits absent timestamps; a data stream would not.

Logstash reads UTF-8 NDJSON from a read-only processed-data mount. Its Ruby filter
creates each event from the preserved payload, removes runtime decorations, validates
the existing ID/timestamp relationship and retains nested evidence and provenance.
Output uses the local credential environment and verified CA.

Ordinary Compose startup leaves input disabled. The wrapper enables the verified file.
Read mode stays alive after EOF; `/dev/null` sincedb means restarting an enabled input
replays the file. Stable IDs prevent count inflation, but this is not a production
checkpoint/recovery system.

## Validation and historical search

Live checks compare counts, mapping, 38 searchable field coverages, timestamp states,
11 representative queries and 13 source-comparison categories across eight records.
Full offline normalization verification complements those indexed source spot checks.
The [report](../analysis/ingestion/ingestion-report.md) and
[JSON](../analysis/ingestion/ingestion-validation.json) retain exact queries and evidence.

Unresolved timestamps stay absent; Logstash must not replace them with ingestion time.
Valid nanosecond instants survive, although insignificant fractional trailing zeros can
change spelling. The corpus spans October–December 2024 despite the dataset's 2025 name.
Use absolute historical times, or omit the time filter to include undated evidence.

In Kibana Dev Tools, inspect unresolved records with:

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

Original payloads and `event.original` are retained in `_source` but not searchable.
Use mapped ECS fields for queries and fetch originals for evidence review. Source
ATT&CK annotations and scenario attribution are context, not detection results.

## Failure handling

Input rejections preserve payloads and reasons at
`/usr/share/logstash/data/rejected-<run_id>.ndjson` in the Logstash volume. Elasticsearch
mapping failures use `/usr/share/logstash/data/dead_letter_queue/main`. Neither is
replayed or deleted automatically. Inspect service logs and run observations under
`analysis/ingestion/runs/`; `latest-run.json` identifies the completed ingestion run.
An empty DLQ can have a one-byte segment header.

Investigate hash/count/mapping failures before rerunning; do not weaken guards or edit
evidence to force success. Continue with [individual detections](individual-detection-implementation.md).
