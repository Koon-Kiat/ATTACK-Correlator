# Sanitization and ECS normalization

Status: preprocessing and ingestion are implemented and validated. This document defines
the preservation and normalization policy used by the existing corpus.

The inspector reads exact CSV headers as strings and JSON types without converting
values. Field identifiers are JSON Pointer paths (`/host/name` differs from a literal
`/host.name`). Missing fields, null/empty values, malformed records, diagnostics and
uninspected files remain visible. CSV `NA` and `null` text are not assumed missing.

CSV and JSONL are streamed with bounded 500-record profiling batches. Standard JSON
documents are loaded only below the explicit size limit. CSV uses a configurable
delimiter and strict UTF-8 with BOM support by default. A CSV quote/encoding failure
can prevent recovery of subsequent records; the report marks the file incomplete.
No duplicate rows are removed. Timestamp-shape probing does not normalize dates or
infer epoch units/timezones. Arrays remain arrays, and JSON wrapper semantics need review.

Field-name hints and ATT&CK-shaped strings guide review only. They cannot establish
that an ATT&CK technique occurred or that a field is reliable ground truth.

## Canonical input and record conservation

`python -m src.preprocessing.preprocess` uses the period-file list and counts in the
verified dataset inspection evidence artifact. It verifies every raw hash against
`analysis/inventory-manifest.json` before writing output and again before publication.
It also verifies the dataset inspection schema, mapping proposals and evidence artifact hashes.
Changed or additional raw files stop processing; the command never edits raw files.

`combined.csv` is verified as evidence but never emitted as additional events. The
scenario mapping CSV is indexed in a temporary SQLite database for exact disk-backed
joins, not treated as telemetry. CSV event records are streamed one at a time. Small
manifest/validation tables and a compact identity-hash index are held in memory; the
entire event corpus is never loaded as a DataFrame. Pandas remains the dataset inspection profiler.

Each parsed source row produces one processed event or one rejection. Exact duplicate
identity/payload combinations are counted and retained, with a quality warning. Similar
events are never deduplicated. Source-identity conflicts are counted. The current corpus
must match dataset inspection total and distinct-identity counts before publication.

Recoverable CSV-width errors and missing `_index`/`_id` produce explicit rejections with
source filename, row index, physical record-end line, identifiers, reason, parsing error,
parsed fields and the full parsed value list (including unmatched extra cells). Fatal
CSV quoting, encoding or header errors stop the complete run because subsequent record
boundaries cannot be trusted. Incomplete staging files are not published as a successful
dataset. A missing/mismatched scenario join also stops publication.

## Original evidence and provenance

Every processed event has `windows_apt.provenance` with the source-relative filename,
zero-based parsed row index, physical record-end line, file SHA-256, original `_index`
and `_id`, representation `period_csv`, dataset/version, processing version and a hash
of the complete parsed row. `event.id` is a project-derived SHA-256 of source filename,
row index and source-file hash; it does not replace either original identifier.

`windows_apt.original` preserves literal source column names and values. It omits only
exact empty strings to avoid repeating hundreds of empty fields per event. Whitespace,
`NA`, `null`, commands, quotes, backslash escaping and all unrecognized fields survive.
`source-schemas.json` records all original headers in order; `clean.restore_row` restores
omitted cells to exact empty strings. The pipeline verifies this round trip for every
processed record. `row_sha256` hashes the full reconstructed dictionary using canonical
UTF-8 JSON, independently of CSV quoting conventions. Original CSV bytes remain raw.

JSON serialization escapes control characters, quotes and newlines without executing or
interpreting them. Suspicious control characters generate warnings; invalid normalized
identifiers/paths are omitted from ECS while the original value remains available.
No HTML decoding, backslash-unescaping, variable expansion or command rewriting occurs.

## Timestamp policy

Only `_source.data.win.system.systemTime` supplies `@timestamp`. The parser requires a
complete ISO date/time with explicit offset and at most nine fractional digits, checks
calendar validity and the Elasticsearch `date_nanos` range, and converts a supplied
offset to UTC without floating point arithmetic. Existing Z values retain every
fractional digit, including trailing zeros. The original string remains in source fields.

`windows_apt.quality.timestamp` is `explicit_utc` for successful conversions and
`unresolved` otherwise. `validated_fallback` is reported as zero: no fallback is currently
justified. Missing or invalid Windows times do not discard events. Such events omit
`@timestamp`; invalid supplied times also carry an `invalid_timestamp` warning.
Display collection times have no verified timezone. Numeric and partial `utcTime`,
`creationUtcTime` and other ambiguous dates remain original evidence, never guessed dates.

The generated offline mapping uses `date_nanos`; ordinary millisecond date mappings
would lose precision. The Logstash configuration preserves unresolved timestamps
without replacing them with ingestion time. Elasticsearch date-nanos aggregations
still have millisecond resolution. [Elastic date_nanos reference](https://www.elastic.co/docs/reference/elasticsearch/mapping-reference/date_nanos).

## Implemented ECS mappings

The implementation is explicit in `normalize.py`; no ATT&CK annotation decides which
observable fields exist. Prefixes below are `W = _source.data.win.eventdata.` and
`S = _source.data.win.system.`. Source values are mapped only when nonempty and valid.

| Source | Target | Context and conversion |
|---|---|---|
| S.systemTime | @timestamp | Explicit validated UTC, nanosecond-preserving |
| S.computer | host.name | Originating Windows computer; not agent/manager alias |
| _source.agent.name / id | agent.name / id | Identifiers stay strings, including leading zeros |
| S.eventID / providerName | event.code / provider | Code is validated 0–65535, emitted as decimal string |
| _source.rule.id | rule.id | Existing source Wazuh rule ID; not a project detection |
| _source.full_log | event.original | Exact original message where supplied; no fabricated message |
| W.image / processGuid / processId | process.executable / entity_id / pid | Reviewed Sysmon actor contexts listed below |
| W.sourceImage / sourceProcessGUID or sourceProcessGuid / sourceProcessId | process.executable / entity_id / pid | Sysmon 8/10 source actor; target process is not substituted |
| W.processName / processId | process.executable / pid | Security-Auditing 4624/4625 caller context; zero PID stays unresolved |
| W.commandLine | process.command_line | Sysmon 1 process creation; exact source command |
| W.parentImage / parentCommandLine / parentProcessGuid / parentProcessId | process.parent.* | Sysmon 1; parent remains distinct from child |
| W.targetFilename | file.path / name | Sysmon 2, 11, 15, 23, 26; valid file path |
| W.targetObject | registry.path | Sysmon 12, 13, 14 and a recognized registry-root prefix |
| W.imageLoaded | dll.path / name | Sysmon 7 module loading |
| W.hashes | process.hash.* / dll.hash.* | Sysmon 1 process image / Sysmon 7 loaded module |
| W.sourceIp / sourcePort / destinationIp / destinationPort | source.* / destination.* | Sysmon 3; validated IP and decimal port |
| W.protocol | network.transport | Sysmon 3; reviewed transport spelling lowercased |
| W.queryName | dns.question.name | Sysmon 22 or DNS-Client 1014 query context; timeout is not success |
| W.user | user.name / domain | Reviewed Sysmon process actor; qualified account split only when unambiguous |
| W.sourceUser | user.name / domain | Sysmon 8/10 source actor; targetUser remains a separate original role |
| W.subjectUserName / subjectDomainName / subjectUserSid | user.name / domain / id | Security-Auditing subject actor; target remains original |

Reviewed Sysmon actor event IDs are 1, 2, 3, 5, 7, 11–15, 17, 18, 22, 23 and 26.
Process IDs are unsigned decimal/hex values within 32 bits. Ports are decimal integers
in 0–65535; IPs use Python's strict IPv4/IPv6 parser, excluding scoped IPv6 suffixes.
GUID validation requires a complete nonzero UUID and preserves source spelling/case.
Conflicting sourceProcessGUID/sourceProcessGuid aliases prevent an actor GUID mapping;
neither is silently selected. A zero caller PID in Security logon events is unavailable
context and does not become a process identity.
Known transport values are tcp, udp, icmp and ipv6-icmp. Unknown values generate warnings.

MD5, SHA1, SHA256 and SHA512 strings require the correct hex length and are lowercased
only in ECS. Conflicting values for the same hash algorithm are withheld and flagged.
IMPHASH remains original PE metadata, not a generic hash. Hashes in other event contexts
remain unmapped. Sysmon `signed`, `initiated`, `sourceIsIpv6` and `destinationIsIpv6`
are validated as true/false strings and stored as booleans under
`windows_apt.observed.flags`; no network direction or binary trust is inferred from them.

`process.name` and parent names come from validated Windows drive/UNC paths or defensible
bare executable filenames (.exe/.com/.scr). Balanced outer quotes may be removed only
in the derived executable value; original evidence is unchanged. Repeated backslashes
are preserved, case is retained, and basename extraction does not interpret escapes.
`System` supplies a process name but no invented executable path. Relative paths,
device paths, alternate streams, unmatched quotes and malformed names stay original
and generate warnings. [Microsoft Sysmon event semantics](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).

The additional caller/DNS contexts were checked against actual source examples and
Microsoft's [4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624),
[4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
and [DNS 1014 timeout documentation](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/ldap-session-takes-longer-target-host-names).
Identical numeric event IDs from other providers never trigger those mappings.

## Deliberately unmapped fields

Windows system-level processID is provider context and never becomes activity PID.
Authentication ipAddress/ipPort are not assigned a direction. Target users never
overwrite actors. Syscheck paths/hashes can represent registry objects and are retained
without forcing filesystem semantics. Process-access target fields, unsupported
provider contexts, numeric clocks and unreviewed executable values stay original.
No host OS/version, event.category, event.type, risk score, severity or malicious/benign
label is inferred. Broad source rules do not become behavioral detections.

## Annotation and enrichment separation

`windows_apt.annotations.attack` holds source ATT&CK IDs, names and tactics; array order
and duplicates are retained. Malformed arrays remain in original/Wazuh metadata and
raise warnings. `windows_apt.annotations.wazuh` holds the nonempty original rule metadata.
The ECS `rule.id` copy is a source identifier only; it is the explicitly documented
exception for source-rule context, not a detector output.

`windows_apt.scenario` is derived publisher attribution. Its ID, name, attribution
strength and derived label come from filename + zero-based row-index lookup. Timestamp,
agent and technique values must agree with the event before enrichment. The entire
mapping row remains in `source_mapping`. `metadata_ref` points to the corresponding
scenario in `publisher-metadata.json`, which preserves manifest and validation tables.
`SHARED-WEAK` stays weak attribution, and untagged does not mean benign. None of this
metadata populates observable process, file, network or timestamp fields.

## Output, quality, and reproducibility

`dataset/processed/windows-apt-events.ndjson` contains compact UTF-8 JSON objects with LF
record endings. `rejected-events.ndjson` exists only when rejections occur. Sidecars are
`source-schemas.json`, `publisher-metadata.json` and `elastic-mapping.json`. These local
data files are Git-ignored while `.gitkeep` remains versionable.

The mapping is an offline contract, not an installed template. It explicitly types ECS
and quality fields, uses strict dynamic mappings, and marks original/Wazuh/publisher
payload objects `enabled: false`. Their values stay in Elasticsearch `_source` without
source dotted keys expanding into conflicting or excessive fields. [Elastic enabled setting](https://www.elastic.co/docs/reference/elasticsearch/mapping-reference/enabled).

`normalization_warnings` records invalid conversions; `mapping_warnings` records
unreviewed semantics. Only populated warning arrays are emitted. Codes/field references
are sorted deterministically; original values provide the detailed evidence.
Generated [summary](../analysis/preprocessing_summary.json) and
[report](../analysis/preprocessing_report.md) contain field coverage, timestamp quality,
IP/port/PID rejects, annotation/scenario coverage, duplicate and conservation statistics.

The [data normalization manifest](../analysis/normalization-manifest.json) records dataset inspection/source hashes,
preprocessing-code hashes, runtime/configuration versions, output/report hashes and
counts. Files are built in a unique local staging directory, verified, then published;
the manifest is written last. Consumers must verify its output hashes. An interrupted
publication is not considered valid until those hashes match. No wall-clock generation
timestamps or temporary paths enter deterministic artifacts. Repeated unchanged runs
must produce identical hashes; source schemas and publisher sidecars must accompany the
NDJSON for complete evidence reconstruction. [Validation record](data-sanitization-and-ecs-normalization.md).

Run `python -m src.preprocessing.verify_processed` to independently stream every
published event/rejection against its actual raw CSV row, validate output/report/code
hashes, confirm record accounting, reconstruct every original row, and check normalized
field shapes against the offline mapping contract. It writes its result to
`analysis/inspection/normalization-verification.json`. This does not connect to Elasticsearch.

## dataset inspection evidence basis

Use the [generated mapping proposals](../analysis/ecs_mapping_candidates.md) and
[source-quality inventory](../analysis/dataset_inventory.md) as the implementation
contract's starting evidence. Period exports support the verified `Source_CSV` plus
zero-based `Row_Index` scenario join. `combined.csv` has changed representations,
including numeric precision and spreadsheet-like errors, and is not a lossless duplicate.
Keep both representations; do not concatenate them into twice as many events.

Prefer explicit Windows `systemTime` where available. Display timestamps lack timezone
information, period `utcTime` can omit the date/hour, and combined `utcTime` can be numeric.
Unsupported timestamps require a visible fallback or quarantine decision, not silent guessing.
Keep original IDs as strings, source hashes/row locations, original field values and
Wazuh/derived-scenario annotations separate from future detection outputs.
