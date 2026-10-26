# Live ingestion validation

Validated: 2026-09-16T12:49:35.435464+00:00. Overall passed: **True**.

Index `windows-apt-events-v1`; template `windows-apt-events-template`; query pattern `windows-apt-events-*`.
Processed SHA-256: `bb2bc4510dba83e445f0c62649de216d6c0f32bda2b5cbe0b43c134ab93121ac`.

Stack versions: Elasticsearch 9.5.3, Logstash 9.5.3, Kibana 9.5.3.
Expected/indexed: 102,011 / 102,011.
Ingestion (container recreation through drain): 69.83 seconds. Index store: 591,317,633 bytes.
Input count before this run: 102,011.

## Failure accounting

```json
{
  "malformed_or_guard_rejected": 0,
  "elasticsearch_non_retryable_failures": 0,
  "elasticsearch_successful_operations": 102011,
  "dead_letter_queue": {
    "max_queue_size_in_bytes": 1073741824,
    "queue_size_in_bytes": 1,
    "dropped_events": 0,
    "last_error": "no errors",
    "storage_policy": "drop_newer",
    "expired_events": 0
  },
  "dead_letter_queue_note": "An empty Logstash DLQ has a one-byte segment header.",
  "logstash_input_events": 102011,
  "logstash_output_events": 102011,
  "passed": true
}
```

## Timestamp and ECS coverage

| Field/check | Expected | Actual | Passed |
|---|---:|---:|---|
| explicit_utc | 90,601 | 90,601 | True |
| unresolved | 11,410 | 11,410 | True |
| validated_fallback | 0 | 0 | True |
| with_timestamp | 90,601 | 90,601 | True |
| without_timestamp | 11,410 | 11,410 | True |
| unresolved_with_timestamp | 0 | 0 | True |
| @timestamp | 90,601 | 90,601 | True |
| agent.id | 102,011 | 102,011 | True |
| agent.name | 102,011 | 102,011 | True |
| destination.ip | 467 | 467 | True |
| destination.port | 467 | 467 | True |
| dll.hash.md5 | 4,112 | 4,112 | True |
| dll.hash.sha1 | 4,112 | 4,112 | True |
| dll.hash.sha256 | 4,112 | 4,112 | True |
| dll.name | 4,112 | 4,112 | True |
| dll.path | 4,112 | 4,112 | True |
| dns.question.name | 3,935 | 3,935 | True |
| event.code | 90,601 | 90,601 | True |
| event.id | 102,011 | 102,011 | True |
| event.provider | 90,601 | 90,601 | True |
| file.name | 22,981 | 22,981 | True |
| file.path | 22,981 | 22,981 | True |
| host.name | 90,601 | 90,601 | True |
| network.transport | 467 | 467 | True |
| process.command_line | 20,814 | 20,814 | True |
| process.entity_id | 51,780 | 51,780 | True |
| process.executable | 55,125 | 55,125 | True |
| process.hash.md5 | 20,814 | 20,814 | True |
| process.hash.sha1 | 16,137 | 16,137 | True |
| process.hash.sha256 | 20,814 | 20,814 | True |
| process.name | 55,313 | 55,313 | True |
| process.parent.command_line | 20,772 | 20,772 | True |
| process.parent.entity_id | 20,758 | 20,758 | True |
| process.parent.executable | 20,772 | 20,772 | True |
| process.parent.name | 20,772 | 20,772 | True |
| process.parent.pid | 20,814 | 20,814 | True |
| process.pid | 55,313 | 55,313 | True |
| registry.path | 947 | 947 | True |
| rule.id | 102,011 | 102,011 | True |
| source.ip | 467 | 467 | True |
| source.port | 467 | 467 | True |
| user.domain | 55,545 | 55,545 | True |
| user.id | 3,774 | 3,774 | True |
| user.name | 55,545 | 55,545 | True |

## Representative searches

Executed Query DSL and exact results are in [ingestion-validation.json](ingestion-validation.json). These KQL equivalents can be used in a later data view; they are not installed detection rules.

| Telemetry | KQL equivalent | Hits |
|---|---|---:|
| process_execution | `event.provider: "Microsoft-Windows-Sysmon" and event.code: "1"` | 20,814 |
| command_line | `process.command_line: *` | 20,814 |
| parent_child | `event.provider: "Microsoft-Windows-Sysmon" and event.code: "1" and process.parent.entity_id: * and process.entity_id: *` | 20,758 |
| file | `file.path: *` | 22,981 |
| registry | `registry.path: *` | 947 |
| network | `source.ip: * and destination.ip: *` | 467 |
| dns | `dns.question.name: *` | 3,935 |
| attack_annotation | `windows_apt.annotations.attack.ids: *` | 63,619 |
| scenario | `windows_apt.scenario.attribution_strength: *` | 102,011 |
| valid_timestamp | `@timestamp: *` | 90,601 |
| unresolved_timestamp | `windows_apt.quality.timestamp: "unresolved" and not @timestamp: *` | 11,410 |

Historical timestamps require an absolute historical time range. Use Dev Tools against the ordinary index without a time filter to include unresolved events.

## Source comparisons

Deterministic first matching records in processed file order; full object comparison except UTC timestamp spelling, plus nanosecond doc-value comparison. All provenance, annotations, scenario, quality and original payloads must match exactly.

| Category | Source row | Exact JSON values | Evidence and date values |
|---|---:|---|---|
| unresolved_timestamp | 0 | True | True |
| original_message | 0 | True | True |
| fractional_timestamp | 1 | True | True |
| attack_annotation | 1 | True | True |
| scenario | 1 | True | True |
| process_execution | 2 | True | True |
| command_line | 2 | True | True |
| parent_child | 2 | True | True |
| file | 15 | True | True |
| dns | 82 | True | True |
| registry | 89 | True | True |
| network | 505 | True | True |
| normalization_warning | 2139 | False | True |

The JSON report retains source filenames, event IDs, original/indexed timestamps, per-namespace comparisons, mapping equality and metadata counts.

## Limitations

- 11,410 unresolved events have no defensible event time; time-filtered views exclude them.
- Logstash may canonicalize insignificant timestamp trailing zeros; instant equality is checked to nanoseconds and original source strings remain exact.
- event.original is intentionally unindexed; it and disabled original/annotation payloads are checked in representative _source comparisons.
- Source annotations and scenario attribution are metadata, not behavioural detections or independent truth.
- Size and duration are local operational observations, not benchmarks. No final detections or dashboard exist.
