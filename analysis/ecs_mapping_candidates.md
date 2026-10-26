# Candidate ECS mappings — proposals only

Generated from raw dataset bytes by `python -m src.preprocessing.evidence_inventory`. The input and output SHA-256 values are retained in `inventory-manifest.json`. This is Phase 2 inspection; no normalization, ingestion, final technique selection or detection rule is implemented.

These are source-semantic proposals, not implemented mappings. The exact source columns and examples below come from the current period corpus. Confidence concerns semantic fit, not proof that all values are valid.

| Dataset Field | Example | Proposed ECS Field | Confidence | Reason |
| --- | --- | --- | --- | --- |
| _source.data.win.system.systemTime | 2024-12-01T06:24:26.902929700Z | @timestamp | Strong | Windows event time includes Z; retain nanoseconds. |
| _source.@timestamp | Nov 30, 2024 @ 20:30:08.057 | event.created (candidate) | Moderate | Displayed collection timestamp has no offset; establish its clock and timezone first. |
| _source.data.win.system.computer | DESKTOP-FMI6MML | host.name | Strong | Windows event's originating computer, not manager. |
| _source.agent.name | Maryam | agent.name | Strong | Collector-assigned agent name; do not silently equate to host.name. |
| _source.agent.id | 0 | agent.id | Strong | Collector agent identifier, not a proven stable device ID. |
| _source.data.win.eventdata.user | NT AUTHORITY\\SYSTEM | user.name + user.domain (split candidate) | Moderate | Process actor is domain-qualified; preserve raw escaping and separate components after review. |
| _source.data.win.eventdata.subjectUserName | DESKTOP-FMI6MML$ | user.name (Security-event context) | Moderate | Security subject actor; targetUserName is a different role and must not overwrite it. |
| _source.data.win.eventdata.subjectDomainName | WORKGROUP | user.domain (Security-event context) | Moderate | Domain of subject actor only. |
| _source.data.win.eventdata.image | C:\\Windows\\SysWOW64\\net1.exe | process.executable; process.name (derived basename) | Strong | Process image; validate escaping and non-path values such as System before deriving name. |
| _source.data.win.eventdata.commandLine | C:\\Windows\\system32\\net1 accounts | process.command_line | Strong | Command line evidence; preserve quotes and backslashes. |
| _source.data.win.eventdata.processId | 0x220 | process.pid | Moderate | Subject process ID; validate decimal/hex. system.processID is provider context. |
| _source.data.win.eventdata.processGuid | {D8AF36FB-011B-674C-6A00-000000000A00} | process.entity_id | Strong | Sysmon process GUID supports identity beyond PID reuse. |
| _source.data.win.eventdata.parentProcessId | 5080 | process.parent.pid | Moderate | Parent process ID; validate numeric representation. |
| _source.data.win.eventdata.parentProcessGuid | {D8AF36FB-011A-674C-6700-000000000A00} | process.parent.entity_id | Strong | Parent GUID must be joined in host context. |
| _source.data.win.eventdata.parentImage | C:\\Windows\\SysWOW64\\net.exe | process.parent.executable; process.parent.name (derived basename) | Strong | Parent image path; validate escaping. |
| _source.data.win.eventdata.parentCommandLine | net.exe accounts | process.parent.command_line | Strong | Parent's command line, distinct from child arguments. |
| _source.data.win.eventdata.targetFilename | C:\\Windows\\assembly\\NativeImages_v4.0.30319_64\\Temp\\12b4-0\\PresentationFramework.Aero2.dll | file.path | Strong | Sysmon target file path; creation is an event fact, not inferred deletion. |
| _source.data.win.eventdata.hashes | MD5=B5A26C2BF17222E86B91D26F1247AF3E,SHA256=14CC5BE4C833ACC652195DEAD113E1C3B4AC0B98EA1AEAD11957836F9AE721CF,IMPHASH=3D3E7537BD3BA07738DC5CA8AD01B073 | process.hash.* / dll.hash.* (event-dependent) | Moderate | Sysmon hashes describe process image or loaded module; not arbitrary file.hash.*. |
| _source.syscheck.sha256_after | 8ed899f3e2ba26b57a4914fb0d0c09c0cd98a96b72ea6345fa6ab894573f1b10 | file.hash.sha256 (filesystem events only) | Moderate | Post-change checksum; syscheck can also refer to registry objects, which need separate semantics. |
| _source.data.win.eventdata.targetObject | HKLM\\System\\CurrentControlSet\\Services\\Fax\\ImagePath | registry.path (registry-event context) | Moderate | Registry object path must not be forced into file.path. |
| _source.data.win.eventdata.sourceIp | 192.168.117.134 | source.ip | Strong | Explicit source endpoint; validate IPv4/IPv6 syntax. |
| _source.data.win.eventdata.sourcePort | 51664 | source.port | Strong | Explicit source port; validate integer range. |
| _source.data.win.eventdata.destinationIp | 185.199.108.133 | destination.ip | Strong | Explicit destination endpoint including loopback; do not assume external traffic. |
| _source.data.win.eventdata.destinationPort | 443 | destination.port | Strong | Explicit destination port; validate integer range. |
| _source.data.win.eventdata.protocol | tcp | network.transport | Moderate | Observed transport value; review spelling/case before later conversion. |
| _source.data.win.eventdata.queryName | wpad | dns.question.name (DNS-event context) | Moderate | DNS query name only where provider/event semantics confirm it. |
| _source.data.win.system.eventID | 4624 | event.code | Strong | Windows event code; retain provider/channel because codes overlap. |
| _source.data.win.system.providerName | Microsoft-Windows-Security-Auditing | event.provider | Strong | Observed Windows event provider. |
| _source.rule.id | 591 | rule.id | Strong | Existing Wazuh rule identifier, not Windows event.code. |
| _source.full_log | ossec: File rotated (inode changed): '/var/log/syslog'. | event.original (where present) | Moderate | Original message exists only for a subset; retain full CSV row provenance too. |

## Explicitly unresolved mappings

- No OS name/version field is inferred from the dataset title or manager name.
- No universal user mapping merges actor, subject and target accounts.
- Numeric utcTime/creationUtcTime values need source-format validation; no epoch or spreadsheet conversion is applied.
- imagePath may contain service command arguments and cannot blindly become process.executable.
- Windows system.processID is provider context, not automatically the activity's process.pid.
- ipAddress/ipPort on authentication events need event-specific direction semantics.
- Original IDs and source row metadata need an explicit identity/provenance contract; mapping-only Source_CSV/Row_Index are join metadata.
- event.category/event.type need a reviewed provider+event-code lookup. They are not direct copied columns.
- Keep Wazuh technique annotations and derived scenario truth in a separate provenance namespace until enrichment semantics are agreed.

## ECS semantics checked

References: [process fields](https://www.elastic.co/docs/reference/ecs/ecs-process), [event fields](https://www.elastic.co/docs/reference/ecs/ecs-event), [host fields](https://www.elastic.co/docs/reference/ecs/ecs-host), [source fields](https://www.elastic.co/docs/reference/ecs/ecs-source), [file fields](https://www.elastic.co/docs/reference/ecs/ecs-file), [registry fields](https://www.elastic.co/docs/reference/ecs/ecs-registry), [user fields](https://www.elastic.co/docs/reference/ecs/ecs-user). The dataset remains the source for field presence and examples. Recheck the selected ECS version in Phase 3.

