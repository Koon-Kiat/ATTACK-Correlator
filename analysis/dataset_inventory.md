# Windows-APT 2025 v4 dataset inventory

Generated from raw dataset bytes by `python -m src.preprocessing.evidence_inventory`. The input and output SHA-256 values are retained in `inventory-manifest.json`. This is Phase 2 inspection; no normalization, ingestion, final technique selection or detection rule is implemented.

## Dataset overview

The raw tree contains **28 files**, including **20 CSVs**. The selected per-period corpus has **102,011 exported rows** and **102,011 distinct source documents/payloads**. The combined export and scenario-mapping table are separate representations, not additional events.

Corpus policy: Per-period exports referenced by mapping; combined.csv is compared separately. Count unit: Distinct (_index, _id, exact nonempty payload) source documents; not confirmed attacks.

## File inventory

| File relative to dataset/raw | Format | Bytes | Parsed rows/documents | Duplicate rows | Complete scan |
| --- | --- | --- | --- | --- | --- |
| windows-apt-2025-v4/Windows-APT 2025 A Dataset for APT-Inspired Attack/01-03-December.csv | csv | 20872574 | 8838 | 0 | True |
| windows-apt-2025-v4/Windows-APT 2025 A Dataset for APT-Inspired Attack/03-04-December.csv | csv | 17586594 | 7291 | 0 | True |
| windows-apt-2025-v4/Windows-APT 2025 A Dataset for APT-Inspired Attack/04-07-December.csv | csv | 17124589 | 7750 | 0 | True |
| windows-apt-2025-v4/Windows-APT 2025 A Dataset for APT-Inspired Attack/07-10-December.csv | csv | 20683573 | 9185 | 0 | True |
| windows-apt-2025-v4/Windows-APT 2025 A Dataset for APT-Inspired Attack/1-11-November.csv | csv | 22217589 | 8807 | 0 | True |
| windows-apt-2025-v4/Windows-APT 2025 A Dataset for APT-Inspired Attack/10-December-P1.csv | csv | 19774595 | 9049 | 0 | True |
| windows-apt-2025-v4/Windows-APT 2025 A Dataset for APT-Inspired Attack/10-December-P2.csv | csv | 2762501 | 1188 | 0 | True |
| windows-apt-2025-v4/Windows-APT 2025 A Dataset for APT-Inspired Attack/11-12-December.csv | csv | 22698392 | 9655 | 0 | True |
| windows-apt-2025-v4/Windows-APT 2025 A Dataset for APT-Inspired Attack/11-16-November.csv | csv | 10787736 | 6554 | 0 | True |
| windows-apt-2025-v4/Windows-APT 2025 A Dataset for APT-Inspired Attack/12-13-December.csv | csv | 15281186 | 6406 | 0 | True |
| windows-apt-2025-v4/Windows-APT 2025 A Dataset for APT-Inspired Attack/13-14-December.csv | csv | 22007210 | 9738 | 0 | True |
| windows-apt-2025-v4/Windows-APT 2025 A Dataset for APT-Inspired Attack/14-17-December.csv | csv | 12018645 | 5644 | 0 | True |
| windows-apt-2025-v4/Windows-APT 2025 A Dataset for APT-Inspired Attack/22-December.csv | csv | 2633050 | 1173 | 0 | True |
| windows-apt-2025-v4/Windows-APT 2025 A Dataset for APT-Inspired Attack/23-30-November.csv | csv | 20879628 | 8038 | 0 | True |
| windows-apt-2025-v4/Windows-APT 2025 A Dataset for APT-Inspired Attack/28-October-01-November.csv | csv | 1428654 | 693 | 0 | True |
| windows-apt-2025-v4/Windows-APT 2025 A Dataset for APT-Inspired Attack/30-November.csv | csv | 4121991 | 2002 | 0 | True |
| windows-apt-2025-v4/Windows-APT 2025 A Dataset for APT-Inspired Attack/checksums.sha256 | sha256 | 1762 | Not tabular telemetry | N/A | N/A |
| windows-apt-2025-v4/Windows-APT 2025 A Dataset for APT-Inspired Attack/combined.csv | csv | 247934817 | 102011 | 0 | True |
| windows-apt-2025-v4/Windows-APT 2025 A Dataset for APT-Inspired Attack/README.md | md | 9214 | Not tabular telemetry | N/A | N/A |
| windows-apt-2025-v4/Windows-APT 2025 A Dataset for APT-Inspired Attack/scenario_manifest.csv | csv | 28317 | 36 | 0 | True |
| windows-apt-2025-v4/Windows-APT 2025 A Dataset for APT-Inspired Attack/scenario_mapping_supplement/build_scenario_mapping_v4.py | py | 31600 | Not tabular telemetry | N/A | N/A |
| windows-apt-2025-v4/Windows-APT 2025 A Dataset for APT-Inspired Attack/scenario_mapping_supplement/log_to_scenario_mapping.csv | csv | 22501323 | 102011 | 0 | True |
| windows-apt-2025-v4/Windows-APT 2025 A Dataset for APT-Inspired Attack/scenario_mapping_supplement/README_supplement_v4.md | md | 4751 | Not tabular telemetry | N/A | N/A |
| windows-apt-2025-v4/Windows-APT 2025 A Dataset for APT-Inspired Attack/scenario_mapping_supplement/scenario_mapping_walkthrough.ipynb | ipynb | 43451 | 1 | 0 | True |
| windows-apt-2025-v4/Windows-APT 2025 A Dataset for APT-Inspired Attack/scripts/load_and_merge_logs.py | py | 4485 | Not tabular telemetry | N/A | N/A |
| windows-apt-2025-v4/Windows-APT 2025 A Dataset for APT-Inspired Attack/scripts/parse_attack_mapping_and_filter.py | py | 6860 | Not tabular telemetry | N/A | N/A |
| windows-apt-2025-v4/Windows-APT 2025 A Dataset for APT-Inspired Attack/scripts/README.md | md | 5088 | Not tabular telemetry | N/A | N/A |
| windows-apt-2025-v4/Windows-APT 2025 A Dataset for APT-Inspired Attack/validation_summary.csv | csv | 7318 | 36 | 0 | True |

A notebook is one JSON document, not one security event. Publisher scripts were inspected as source text and never executed. Checksums, readable status, exact columns, typed examples, nulls and distinct-value limits are in `dataset_schema.json`.

## Data quality and overlap

| Check | Observed result |
| --- | --- |
| Empty files | [] |
| Unreadable files | [] |
| Malformed structured records | 0 |
| Incomplete structured scans | [] |
| Exact duplicate exported rows in period corpus | 0 |
| Repeated document identities | 0 |
| Identities with conflicting payloads | 0 |
| Combined rows | 102011 |
| Positional joins with equal _index/_id | 102011 |
| Positional identity mismatches | 0 |
| Exact aligned-payload overlap with period files | 36674 |
| Combined-only payload rows | 65337 |
| Period-only payload rows | 65337 |
| Malformed event label arrays | [] |

Overlap comparison aligns column names and treats an absent column like an empty cell; all nonempty values, including whitespace and numeric spelling, remain exact. Duplicate handling affects analytical counts only; no source row is removed. Zero parse failures does not establish semantically complete telemetry. JSON null/whitespace empties are counted separately from absent columns. Literal NA/null strings remain source values. Distinct-value counts capped at 10,000 are labelled lower bounds.

### Representation differences

| Source field | Changed rows | Period file and row | Period value | Combined value |
| --- | --- | --- | --- | --- |
| _source.agent.id | 14937 | 03-04-December.csv:0 | 003 | 3 |
| _source.data.level | 2 | 11-16-November.csv:62 | 90% | 0.9 |
| _source.data.sca.check.compliance.cis_csc | 1 | 03-04-December.csv:2167 | 4.10 | 4.1 |
| _source.data.win.eventdata.binary | 509 | 01-03-December.csv:87 | 4.60061E+15 | 4.60E+15 |
| _source.data.win.eventdata.creationUtcTime | 22980 | 01-03-December.csv:15 | 26:00.7 | 45627.26806 |
| _source.data.win.eventdata.destinationIsIpv6 | 48 | 03-04-December.csv:15 | true | TRUE |
| _source.data.win.eventdata.initiated | 48 | 03-04-December.csv:15 | false | FALSE |
| _source.data.win.eventdata.nTSTATUS | 3 | 03-04-December.csv:1224 | 00000000 | 0 |
| _source.data.win.eventdata.param3 | 3 | 03-04-December.csv:2151 | --com-service | #NAME? |
| _source.data.win.eventdata.passwordLastSet | 23 | 01-03-December.csv:2308 | 11/26/2024 1:41 | 45622.07014 |
| _source.data.win.eventdata.previousCreationUtcTime | 1 | 22-December.csv:431 | 39:27.1 | 0.027396991 |
| _source.data.win.eventdata.signed | 806 | 03-04-December.csv:217 | true | TRUE |
| _source.data.win.eventdata.sourceIsIpv6 | 48 | 03-04-December.csv:15 | true | TRUE |
| _source.data.win.eventdata.targetUserName | 3 | 1-11-November.csv:5959 | None |  |
| _source.data.win.eventdata.utcTime | 57634 | 01-03-December.csv:2 | 24:27.7 | 45627.26699 |
| _source.data.win.logFileCleared.clientProcessStartKey | 1 | 1-11-November.csv:6367 | 1.40737E+15 | 1.41E+15 |
| _source.id | 14937 | 03-04-December.csv:0 | 1733171439.18747 | 1733171439 |
| _source.predecoder.timestamp | 263 | 01-03-December.csv:2534 | 12/2/2025 15:12 | 45628.63363 |
| _source.rule.mail | 14937 | 03-04-December.csv:0 | false | FALSE |

Field differences are compared only after confirming equal document identities. They include changes in representation, not additional events. Review numeric precision, lost leading zeros, case changes, partial-clock strings and spreadsheet error values. Prefer period files for the verified scenario join, but retain combined.csv for comparison because neither representation is uniformly lossless.

## Log sources

### _source.data.win.system.providerName

| Observed value | Export rows |
| --- | --- |
| Microsoft-Windows-Sysmon | 57634 |
| Windows Error Reporting | 14533 |
| (missing) | 11410 |
| Microsoft-Windows-Security-SPP | 4111 |
| Microsoft-Windows-DNS-Client | 3935 |
| Microsoft-Windows-Security-Auditing | 3875 |
| Application Error | 2061 |
| Service Control Manager | 1307 |
| MsiInstaller | 924 |
| Application Hang | 589 |
| Microsoft-Windows-DistributedCOM | 581 |
| ESENT | 356 |
| Microsoft-Windows-Winlogon | 199 |
| VSS | 162 |
| Microsoft-Windows-Eventlog | 81 |
| Microsoft-Windows-TPM-WMI | 66 |
| Microsoft-Windows-Search | 63 |
| Microsoft-Windows-WMI | 48 |
| Microsoft-Windows-User Profiles Service | 31 |
| Microsoft-Windows-MSDTC Client 2 | 12 |
| Microsoft-Windows-WindowsUpdateClient | 10 |
| Microsoft-Windows-PerfNet | 5 |
| .NET Runtime | 3 |
| Microsoft-Windows-MSDTC 2 | 3 |
| Microsoft-Windows-Perflib | 3 |
| Microsoft-Windows-WinRM | 3 |
| Volsnap | 3 |
| Microsoft-Windows-WER-SystemErrorReporting | 2 |
| stornvme | 1 |

### _source.data.win.system.channel

| Observed value | Export rows |
| --- | --- |
| Microsoft-Windows-Sysmon/Operational | 57634 |
| Application | 23103 |
| (missing) | 11410 |
| System | 5983 |
| Security | 3881 |

### _source.decoder.name

| Observed value | Export rows |
| --- | --- |
| windows_eventchannel | 90601 |
| syscheck_registry_value_added | 4036 |
| sca | 2329 |
| syscheck_registry_value_modified | 1562 |
| syscheck_registry_key_modified | 905 |
| syscheck_registry_key_added | 860 |
| syscheck_registry_value_deleted | 760 |
| ossec | 328 |
| rootcheck | 257 |
| pam | 185 |
| sudo | 74 |
| syscheck_integrity_changed | 46 |
| syscheck_new_entry | 21 |
| dpkg-decoder | 18 |
| syscheck_deleted | 8 |
| syscheck_registry_key_deleted | 7 |
| wazuh | 5 |
| syscollector | 4 |
| (missing) | 2 |
| ar_log_json | 1 |
| groupadd | 1 |
| useradd | 1 |

### _source.location

| Observed value | Export rows |
| --- | --- |
| EventChannel | 90601 |
| syscheck | 8205 |
| sca | 2329 |
| /var/log/auth.log | 261 |
| rootcheck | 257 |
| wazuh-agent | 108 |
| netstat listening ports | 105 |
| wazuh-monitord | 95 |
| /var/log/dpkg.log | 18 |
| logcollector | 13 |
| wazuh-remoted | 7 |
| df -P | 5 |
| syscollector | 4 |
| /var/log/syslog | 2 |
| active-response\active-responses.log | 1 |

### _source.input.type

| Observed value | Export rows |
| --- | --- |
| log | 102011 |

## Hosts and dataset-provided context

| Agent name | Documents | With Wazuh ATT&amp;CK labels | With Windows UTC time |
| --- | --- | --- | --- |
| DESKTOP-DS4FBF4 | 3435 | 2639 | 2726 |
| Maryam | 962 | 222 | 0 |
| agent1 | 17665 | 3532 | 14668 |
| wazuh-agent | 23772 | 13868 | 20792 |
| window-agent3 | 56177 | 43358 | 52415 |

The supplement README identifies Maryam as infrastructure. Its rows are a **candidate** background pool, not an independently labelled benign set; the table explicitly shows any existing technique tags. Agent labels and originating Windows computer names are different fields. No OS-name/version column is supplied by the inspected event schema; syscheck architecture describes checked objects and must not be assumed to be the host OS.

## Available telemetry

All following source columns actually exist. Counts use exported period rows; examples are exact prefixes with truncation noted. Full schemas and per-file null, type, distinct and embedded-JSON statistics are in `dataset_schema.json`.

### event metadata

| Dataset field | Nonempty rows | Empty or absent rows | Example |
| --- | --- | --- | --- |
| _index | 102011 | 0 | wazuh-alerts-4.x-2024.11.30 |
| _id | 102011 | 0 | MPrEfpMBRlc-D5DFQSbD |
| _source.id | 102011 | 0 | 1732998608 |
| _source.@timestamp | 102011 | 0 | Nov 30, 2024 @ 20:30:08.057 |
| _source.timestamp | 102011 | 0 | Nov 30, 2024 @ 20:30:08.057 |
| _source.data.win.system.systemTime | 90601 | 11410 | 2024-12-01T06:24:26.902929700Z |
| _source.data.win.system.eventID | 90601 | 11410 | 4624 |
| _source.data.win.system.providerName | 90601 | 11410 | Microsoft-Windows-Security-Auditing |
| _source.data.win.system.channel | 90601 | 11410 | Security |
| _source.decoder.name | 102009 | 2 | ossec |
| _source.location | 102011 | 0 | logcollector |
| _source.input.type | 102011 | 0 | log |
| _source.rule.id | 102011 | 0 | 591 |
| _source.rule.description | 101953 | 58 | Log file rotated. |
| _source.full_log | 9192 | 92819 | ossec: File rotated (inode changed): '/var/log/syslog'. |

### host

| Dataset field | Nonempty rows | Empty or absent rows | Example |
| --- | --- | --- | --- |
| _source.agent.name | 102011 | 0 | Maryam |
| _source.agent.id | 102011 | 0 | 0 |
| _source.agent.ip | 100530 | 1481 | 192.168.117.130 |
| _source.data.win.system.computer | 90601 | 11410 | DESKTOP-FMI6MML |
| _source.manager.name | 102011 | 0 | Maryam |
| _source.predecoder.hostname | 261 | 101750 | Maryam |

### user authentication

| Dataset field | Nonempty rows | Empty or absent rows | Example |
| --- | --- | --- | --- |
| _source.data.win.eventdata.user | 49331 | 52680 | NT AUTHORITY\\SYSTEM |
| _source.data.win.eventdata.parentUser | 20758 | 81253 | NT AUTHORITY\\SYSTEM |
| _source.data.win.eventdata.subjectUserName | 3761 | 98250 | DESKTOP-FMI6MML$ |
| _source.data.win.eventdata.subjectDomainName | 3761 | 98250 | WORKGROUP |
| _source.data.win.eventdata.subjectUserSid | 3774 | 98237 | S-1-5-18 |
| _source.data.win.eventdata.targetUserName | 3683 | 98328 | SYSTEM |
| _source.data.win.eventdata.targetDomainName | 3662 | 98349 | NT AUTHORITY |
| _source.data.win.eventdata.targetUserSid | 3629 | 98382 | S-1-5-18 |
| _source.data.win.eventdata.logonId | 20814 | 81197 | 0x3e7 |
| _source.data.win.eventdata.logonGuid | 24286 | 77725 | {00000000-0000-0000-0000-000000000000} |
| _source.data.win.eventdata.logonType | 3612 | 98399 | 5 |
| _source.data.win.eventdata.authenticationPackageName | 3542 | 98469 | Negotiate |
| _source.data.win.eventdata.sourceUser | 2461 | 99550 | DESKTOP-QGB4EQH\\mari |
| _source.data.win.eventdata.targetUser | 2461 | 99550 | DESKTOP-QGB4EQH\\mari |
| _source.data.srcuser | 148 | 101863 | mari |
| _source.data.dstuser | 261 | 101750 | root(uid=0) |

### process

| Dataset field | Nonempty rows | Empty or absent rows | Example |
| --- | --- | --- | --- |
| _source.data.win.eventdata.image | 49323 | 52688 | C:\\Windows\\SysWOW64\\net1.exe |
| _source.data.win.eventdata.processName | 3605 | 98406 | C:\\Windows\\System32\\services.exe |
| _source.data.win.eventdata.commandLine | 20814 | 81197 | C:\\Windows\\system32\\net1 accounts |
| _source.data.win.eventdata.processId | 52941 | 49070 | 0x220 |
| _source.data.win.eventdata.processGuid | 49323 | 52688 | {D8AF36FB-011B-674C-6A00-000000000A00} |
| _source.data.win.eventdata.parentProcessId | 20814 | 81197 | 5080 |
| _source.data.win.eventdata.parentProcessGuid | 20814 | 81197 | {D8AF36FB-011A-674C-6700-000000000A00} |
| _source.data.win.eventdata.parentImage | 20772 | 81239 | C:\\Windows\\SysWOW64\\net.exe |
| _source.data.win.eventdata.parentCommandLine | 20772 | 81239 | net.exe accounts |
| _source.data.win.eventdata.sourceImage | 2461 | 99550 | C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe |
| _source.data.win.eventdata.targetImage | 2461 | 99550 | C:\\Windows\\Explorer.EXE |
| _source.data.win.eventdata.sourceProcessId | 2461 | 99550 | 4260 |
| _source.data.win.eventdata.targetProcessId | 2461 | 99550 | 4728 |
| _source.data.win.eventdata.sourceProcessGUID | 2438 | 99573 | {15959494-01B4-674C-4B01-000000000F00} |
| _source.data.win.eventdata.targetProcessGUID | 2438 | 99573 | {15959494-0017-674C-6000-000000000F00} |
| _source.data.win.eventdata.sourceProcessGuid | 23 | 101988 | {15959494-69E3-674D-6102-000000001200} |
| _source.data.win.eventdata.targetProcessGuid | 23 | 101988 | {15959494-57D1-674D-0C00-000000001200} |
| _source.data.win.eventdata.grantedAccess | 2438 | 99573 | 0x1410 |
| _source.data.win.eventdata.imageLoaded | 4112 | 97899 | C:\\Windows\\System32\\taskschd.dll |
| _source.data.win.eventdata.utcTime | 57634 | 44377 | 24:27.7 |

### file registry

| Dataset field | Nonempty rows | Empty or absent rows | Example |
| --- | --- | --- | --- |
| _source.data.win.eventdata.targetFilename | 22981 | 79030 | C:\\Windows\\assembly\\NativeImages_v4.0.30319_64\\Temp\\12b4-0\\PresentationFramework.Aero2.dll |
| _source.data.win.eventdata.creationUtcTime | 22980 | 79031 | 26:00.7 |
| _source.data.win.eventdata.hashes | 24927 | 77084 | MD5=B5A26C2BF17222E86B91D26F1247AF3E,SHA256=14CC5BE4C833ACC652195DEAD113E1C3B4AC0B98EA1AEAD11957836F9AE721CF,IMPHASH=3D3E7537BD3BA07738DC5CA8AD01B073 |
| _source.data.win.eventdata.targetObject | 947 | 101064 | HKLM\\System\\CurrentControlSet\\Services\\Fax\\ImagePath |
| _source.data.win.eventdata.eventType | 957 | 101054 | SetValue |
| _source.data.win.eventdata.details | 947 | 101064 | C:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe -noexit -c \"write-host 'T1543.003 Test'\" |
| _source.syscheck.path | 8205 | 93806 | HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\AppIso\FirewallRules |
| _source.syscheck.event | 8205 | 93806 | deleted |
| _source.syscheck.mode | 8205 | 93806 | scheduled |
| _source.syscheck.changed_attributes | 2513 | 99498 | ["mtime"] |
| _source.syscheck.mtime_before | 951 | 101060 | 2024-09-22T00:47:26 |
| _source.syscheck.mtime_after | 1850 | 100161 | 2024-12-02T10:16:06 |
| _source.syscheck.md5_after | 6430 | 95581 | f9111ad9f15a7e601256e686d79555a3 |
| _source.syscheck.sha1_after | 6430 | 95581 | 78e5e8094a97583800f1ee8720423ef59139b2ad |
| _source.syscheck.sha256_after | 6430 | 95581 | 8ed899f3e2ba26b57a4914fb0d0c09c0cd98a96b72ea6345fa6ab894573f1b10 |
| _source.syscheck.sha256_before | 1566 | 100445 | 4850c85842656a7c58a4209172fefcc2786b27927f08e527dd4df7f4131f349c |
| _source.syscheck.value_type | 6355 | 95656 | REG_SZ |

### network

| Dataset field | Nonempty rows | Empty or absent rows | Example |
| --- | --- | --- | --- |
| _source.data.win.eventdata.sourceIp | 467 | 101544 | 192.168.117.134 |
| _source.data.win.eventdata.sourcePort | 467 | 101544 | 51664 |
| _source.data.win.eventdata.destinationIp | 467 | 101544 | 185.199.108.133 |
| _source.data.win.eventdata.destinationPort | 467 | 101544 | 443 |
| _source.data.win.eventdata.protocol | 467 | 101544 | tcp |
| _source.data.win.eventdata.ipAddress | 133 | 101878 | 192.168.117.130 |
| _source.data.win.eventdata.ipPort | 133 | 101878 | 52369 |
| _source.data.win.eventdata.queryName | 3935 | 98076 | wpad |
| _source.data.win.eventdata.sourceHostname | 14 | 101997 | DESKTOP-FMI6MML.localdomain |
| _source.data.win.eventdata.destinationHostname | 14 | 101997 | cdn-185-199-108-133.github.com |

### attack annotations

| Dataset field | Nonempty rows | Empty or absent rows | Example |
| --- | --- | --- | --- |
| _source.rule.mitre.id | 63619 | 38392 | ["T1078"] |
| _source.rule.mitre.technique | 63619 | 38392 | ["Valid Accounts"] |
| _source.rule.mitre.tactic | 63619 | 38392 | ["Defense Evasion","Persistence","Privilege Escalation","Initial Access"] |
| _source.rule.mitre_techniques | 170 | 101841 | ["T1078","T1078.001","T1078.002","T1078.003","T1078.004","T1110","T1110.001","T1110.002","T1110.003"] |
| _source.data.sca.check.compliance.mitre_techniques | 170 | 101841 | T1078,T1078.001,T1078.002,T1078.003,T1078.004,T1110,T1110.001,T1110.002,T1110.003 |

### wmi context

| Dataset field | Nonempty rows | Empty or absent rows | Example |
| --- | --- | --- | --- |
| _source.data.win.eventdata.name | 8 | 102003 |  \"AtomicRedTeam_consumer\" |
| _source.data.win.eventdata.destination | 8 | 102003 |  \"cmd.exe\" |
| _source.data.win.eventdata.type | 9 | 102002 | Command Line |
| _source.data.win.eventdata.operation | 38 | 101973 | %%2480 |

## Timestamp observations

| Check | Measured result |
| --- | --- |
| windows_utc_time_events | 90601 |
| display_time_events | 102011 |
| display_minus_windows_utc_wall_clock | {"count": 90601, "max_seconds": 58631.921574, "median_seconds": 0.870984, "min_seconds": -12183.297654, "p95_seconds": 27.029421} |
| excel_1899_12_30_hypothesis_vs_embedded_utcTime | {"count": 65, "max_seconds": 0.415, "median_seconds": -0.064, "min_seconds": -3942061200.021035, "p95_seconds": 0.397} |
| serial_comparisons_within_one_second | 57 |
| serial_comparison_outliers | [{"combined_value": "0.021925926", "difference_seconds": -3941873999.988994, "embedded_original_utcTime": "2024-11-27 13:31:34.389", "row_index": 1848, "source_csv": "23-30-November.csv"}, {"combined_value": "0.015659722", "difference_seconds": -3941737199.993019, "embedded_original_utcTime": "2024-11-25 23:22:32.993", "row_index": 3001, "source_csv": "23-30-November.csv"}, {"combined_value": "0.006568287", "difference_seconds": -3941776800.014003, "embedded_original_utcTime": "2024-11-26 10:09:27.514", "row_index": 3474, "source_csv": "23-30-November.csv"}, {"combined_value": "0.006025463", "difference_seconds": -3941776799.994997, "embedded_original_utcTime": "2024-11-26 10:08:40.595", "row_index": 3475, "source_csv": "23-30-November.csv"}, {"combined_value": "0.009988426", "difference_seconds": -3942061200.005994, "embedded_original_utcTime": "2024-11-29 17:14:23.006", "row_index": 5234, "source_csv": "23-30-November.csv"}, {"combined_value": "0.016216435", "difference_seconds": -3941737199.971016, "embedded_original_utcTime": "2024-11-25 23:23:21.071", "row_index": 5486, "source_csv": "23-30-November.csv"}, {"combined_value": "0.021505787", "difference_seconds": -3941874000.009003, "embedded_original_utcTime": "2024-11-27 13:30:58.109", "row_index": 7225, "source_csv": "23-30-November.csv"}, {"combined_value": "0.010719907", "difference_seconds": -3942061200.021035, "embedded_original_utcTime": "2024-11-29 17:15:26.221", "row_index": 7936, "source_csv": "23-30-November.csv"}] |
| hypothesis_note | Diagnostic comparison only; no serial conversion or timezone policy applied to source data |

The display timestamp lacks a timezone; its difference from UTC event time is a wall-clock diagnostic, not a verified timezone offset. Numeric utcTime values are tested against the Excel 1899-12-30 hypothesis only where an embedded original UTC string exists. That comparison is not a normalization policy; rounding/precision and source-clock meaning must be settled in Phase 3. Correlation exploration uses only explicit-offset Windows systemTime and excludes rows without it. Microseconds are used for interval calculations; original strings preserve greater precision.

### Original-message availability

| Full-log representation | Rows |
| --- | --- |
| plain_or_unparsed_text | 9127 |
| dict | 65 |

Plain-text original messages are legitimate formats, not automatically malformed JSON. Preserve the CSV row when full_log is absent.

## Scenarios and ground truth

Manifest rows: **36**; validation rows: **36**; mapping rows: **102,011**.

| Metadata file | Observed columns |
| --- | --- |
| scenario_manifest.csv | ["Scenrario_ID", "Scenario_Name", "Mitre_Groups", "Reported_Origin", "Simiulated Tactics", "Simulated Techniques", "Expected_artifacts", "Reference"] |
| validation_summary.csv | ["Scenrario_ID", "Scenario_Name", "Total_runs", "Expected_techniques_count", "Avg_techniques_succeeded_per_run", "Avg_success_ratio", "Anomalies_notes", "Secondary_reviewed", "Validation_checks"] |
| log_to_scenario_mapping.csv | ["Row_Index", "Source_CSV", "Timestamp", "Agent_Name", "MITRE_Technique", "Scenario_ID", "Scenario_Name", "MITRE_Group_ID", "Scenario_Posterior", "Derived_Label", "Attribution_Strength", "Mapping_Evidence", "Candidate_Scenarios"] |

Manifest/validation use the source spelling `Scenrario_ID`; mapping uses `Scenario_ID`. The verified event join is `(Source_CSV, Row_Index)` with **zero-based parsed row indices in each period CSV**. A physical file line is different when CSV fields contain newlines.

| Join check | Result |
| --- | --- |
| Matched event rows | 102011 |
| Unmatched event rows | 0 |
| Orphan mapping keys | 0 |
| Duplicate mapping keys | 0 |
| Timestamp / Agent_Name / MITRE_Technique mismatches | {"Agent_Name": 0, "MITRE_Technique": 0, "Timestamp": 0} |
| Unknown assigned scenarios | 0 |
| Mapping source files | ["01-03-December.csv", "03-04-December.csv", "04-07-December.csv", "07-10-December.csv", "1-11-November.csv", "10-December-P1.csv", "10-December-P2.csv", "11-12-December.csv", "11-16-November.csv", "12-13-December.csv", "13-14-December.csv", "14-17-December.csv", "22-December.csv", "23-30-November.csv", "28-October-01-November.csv", "30-November.csv"] |

The README's example join using Source_CSV=combined.csv does not match this supplied mapping, whose keys name period CSVs. The supplement README also refers to Subset_masked_by, which is absent from the inspected mapping schema. MITRE_Group_ID contains dataset-provided group names; preserve it without pretending those values are canonical G-number IDs.

| Attribution_Strength | Rows |
| --- | --- |
| NARROWED | 5913 |
| SHARED-WEAK | 89820 |
| UNIQUE-MATCH | 373 |
| UNRESOLVED | 5905 |

| Derived_Label | Rows |
| --- | --- |
| NA | 42 |
| technique-tagged | 63491 |
| technique-unmatched | 86 |
| untagged | 38392 |

These are post-hoc scenario attributions derived from Wazuh technique tags and episode context. UNIQUE-MATCH/NARROWED are stronger assignments within that method, not independently verified attacks. Untagged does not mean benign. The supplied metadata has no observed per-event binary malicious/benign ground-truth column, attack-step ID or authoritative scenario start/end boundaries. Observed event min/max times do not replace execution boundaries.

### Expected-versus-observed metadata checks

| Scenario | Manifest IDs | Declared expected | Avg succeeded | Reported % | Avg/declared % |
| --- | --- | --- | --- | --- | --- |
| S01 | 14 | 14 | 11.0 | 85.0 | 78.571 |
| S02 | 2 | 2 | 2.0 | 100.0 | 100.0 |
| S03 | 18 | 18 | 14.0 | 82.0 | 77.778 |
| S04 | 2 | 2 | 2.0 | 100.0 | 100.0 |
| S05 | 17 | 17 | 14.0 | 88.0 | 82.353 |
| S06 | 25 | 25 | 20.0 | 83.0 | 80.0 |
| S07 | 74 | 74 | 52.0 | 78.0 | 70.27 |
| S08 | 34 | 34 | 25.0 | 81.0 | 73.529 |
| S09 | 13 | 13 | 10.0 | 83.0 | 76.923 |
| S10 | 8 | 8 | 7.0 | 88.0 | 87.5 |
| S11 | 20 | 20 | 16.0 | 84.0 | 80.0 |
| S12 | 4 | 4 | 3.0 | 75.0 | 75.0 |
| S13 | 3 | 3 | 3.0 | 100.0 | 100.0 |
| S14 | 31 | 31 | 23.0 | 79.0 | 74.194 |
| S15 | 22 | 22 | 17.0 | 81.0 | 77.273 |
| S16 | 38 | 38 | 28.0 | 80.0 | 73.684 |
| S17 | 4 | 4 | 3.0 | 75.0 | 75.0 |
| S18 | 16 | 16 | 13.0 | 87.0 | 81.25 |
| S19 | 3 | 3 | 3.0 | 100.0 | 100.0 |
| S20 | 4 | 4 | 3.0 | 75.0 | 75.0 |
| S21 | 6 | 6 | 5.0 | 83.0 | 83.333 |
| S22 | 4 | 4 | 3.0 | 75.0 | 75.0 |
| S23 | 14 | 14 | 11.0 | 85.0 | 78.571 |
| S24 | 10 | 10 | 9.0 | 90.0 | 90.0 |
| S25 | 28 | 28 | 22.0 | 85.0 | 78.571 |
| S26 | 45 | 45 | 32.0 | 78.0 | 71.111 |
| S27 | 25 | 25 | 20.0 | 83.0 | 80.0 |
| S28 | 78 | 78 | 54.0 | 77.0 | 69.231 |
| S29 | 29 | 29 | 22.0 | 81.0 | 75.862 |
| S30 | 7 | 7 | 6.0 | 86.0 | 85.714 |
| S31 | 19 | 19 | 15.0 | 83.0 | 78.947 |
| S32 | 43 | 43 | 32.0 | 80.0 | 74.419 |
| S33 | 48 | 48 | 35.0 | 80.0 | 72.917 |
| S34 | 59 | 60 | 43.0 | 80.0 | 71.667 |
| S35 | 92 | 92 | 64.0 | 77.0 | 69.565 |
| S36 | 36 | 36 | 27.0 | 82.0 | 75.0 |

The recalculated ratio is a consistency check, not detection accuracy. Differences may reflect rounded averages or different denominators in the publisher's validation notes; these summaries cannot supply event-level TP/FP/FN/TN.

## Phase 3 questions

Settle event versus collection time, serial-date precision, escaped strings, provider-aware event semantics, explicit rejection accounting, source identity and row-index preservation. Use the verified period-file join and keep original and derived labels apart from detector inputs. Review raw examples of each candidate before selecting the final three in the later selection phase.

