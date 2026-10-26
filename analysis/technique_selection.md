# Phase 5: evidence-based sub-technique selection

Selected on 13 September 2026 (Singapore): **T1059.001 PowerShell, T1059.003 Windows
Command Shell, and T1543.003 Windows Service**. These are exactly three distinct
sub-techniques. This phase defines detection contracts and verifies relationships;
final KQL, ES|QL, EQL, Security rules and dashboard implementation remain pending.

## Evidence scope and method

The Phase 2 [inventory](attack_coverage.md) and [evidence](attack_evidence.json) supplied
candidate context. Phase 3 preserved source semantics and Phase 4 established the live
index. Read-only validation of `windows-apt-events-*` still passes: **102,011 events,
90,601 with `@timestamp`, 11,410 without a defensible timestamp**. Historical UTC times
are retained. This phase did not repeat preprocessing or ingestion.

For later time-filtered inspection, use an absolute UTC range covering **29 October
through 22 December 2024** (an exclusive upper bound of 23 December includes the final
day). Phase 4's min/max summary has millisecond aggregation precision; relationship
checks use each record's preserved nanosecond timestamp. Unfiltered standalone searches
are necessary to include undated records.

The [29 saved exploratory queries](selection/exploratory-queries.json) filter provider,
event code, process, command, registry, file or network fields. Source ATT&CK annotations,
Wazuh rules and scenario assignments are returned only as review context. They are not
query predicates or correlation keys. Counts describe matching event documents, not
attacks. An attempted command, an installation, a registry write and a process launch
have different meanings and denominators.

The [selection JSON](technique_selection.json) retains contracts, exact event IDs,
timestamps, host/user/process/object fields, original service fields, source filenames,
zero-based rows and hashes. The [correlation evidence](selection/correlation-feasibility.json)
retains actual distinct documents and exact nanosecond gaps. The
[verification report](selection/selection-verification.json) records live replay results.

## Candidate comparison and timestamp suitability

Strong/Moderate/Weak rates suitability for this project's observable detection and
correlation design, not certainty of malicious intent. Counts below are behavioural
cohorts; none is an annotation count. `Timed / undated` refers to valid indexed event
time within that cohort. All nonempty cohorts listed here have **100% usable time**.

| Candidate | Observable cohort; timed / undated | Actor / parent GUID coverage in main cohort | Assessment and decision |
|---|---|---|---|
| **T1059.001 PowerShell** | 2,060 launches; 2,060 / 0. Broad encoded-or-bypass probe: 1,726 / 0 | 2,060 / 2,021 | **Strong, selected.** Commands, ancestry, child-shell relationships and routine-command comparison; clear process/argument dashboard evidence. |
| **T1059.003 Windows Command Shell** | 7,717 launches; 7,717 / 0. Service-parent shells: 3 / 0 | 7,717 / 7,706 | **Strong, selected.** Arguments and retrieved child processes support separate shell analytics, parent comparisons and evidence tables. |
| **T1543.003 Windows Service** | 102 installations; 102 / 0. Separate cohorts: 155 create commands, 117 binPath configuration commands, 708 ImagePath writes; all timed, zero undated | Installation: 0 / 0; command cohorts: 155 / 155 and 117 / 117; registry: 708 / 0 | **Strong, selected.** Direct installation records, independent process/registry evidence and full-command object matches. Legitimate update candidates support discussion. |
| T1053.005 Scheduled Task | 59 creation commands; 59 / 0; one TaskCache write | 59 / 59 | **Moderate, rejected.** Good command evidence and CAR guidance, but no 4698/4702, TaskScheduler provider or actual Tasks-directory creation records. Outcome corroboration is weaker than Service. |
| T1548.002 Bypass User Account Control | 98 ms-settings registry events; 98 / 0; 86 auto-elevated utility launches | Registry: 98 / 0 | **Moderate, rejected.** Suggestive activity, but consent bypass/elevated-child outcome and complete actor lineage are unestablished. Registry/utility counts alone could mislead a dashboard. |
| T1070.004 File Deletion | 217 command attempts; 217 / 0; one native deletion event | Commands: 217 / 217; native deletion: 1 / 0 | **Weak, rejected.** The single Sysmon 26 example is a compiler temporary DLL; command intent is not observed deletion or anti-forensic intent. Routine cleanup is plausible. |
| T1574.001 DLL | 4,112 module loads; 4,112 / 0 | 4,108 / 0 | **Weak, rejected.** Generic loads are not 4,112 hijacks. Replacement/search-order manipulation followed by an unexpected load is unestablished. Routine DLL loads limit interpretation. |
| T1027.004 Compile After Delivery | 666 csc.exe launches; 666 / 0 | 666 / 666 | **Moderate, rejected.** Compilation is visible, but delivery and subsequent payload execution are unconfirmed; developer/build activity is a plausible alternative. |
| T1021.006 Windows Remote Management | 376 destination-port 5985/5986 connections; 376 / 0 | 376 / 0 | **Moderate, rejected.** Port observations support investigation, but zero wsmprovhost.exe child-process records weaken remote-execution correlation. Normal remote management also matches. |

Registry, module and network GUIDs identify the observing actor, not a newly created
process. A parent GUID does not guarantee that its creation document exists. Zero-result
cohorts have no percentage, rather than an invented 100%. Additional Run-key and Visual
Basic host probes remain triage observations. No strong relationship with the final trio
was established for the rejected candidates during this bounded review; this does not
prove that none exists.

Two selected IDs share parent T1059. Their separate interpreters, arguments and actual
parent/child documents permit distinct detection contracts. T1543.003 adds service
installation/configuration, Persistence and Privilege Escalation, and independent System
and registry observations. The verified service → shell → PowerShell relationship gives
the trio analytical breadth without relying on unrelated labels.

## Observable contracts and Phase 6 plans

All baselines require `event.id`, `event.provider`, `event.code` and `host.name`.
Process variants additionally require `process.name`, `process.executable` and
`process.command_line`. Missing command content must remain visible as a coverage gap.
`@timestamp`, `process.entity_id` and `process.parent.entity_id` become mandatory for
ordered process correlation. `user.name`, `user.domain`, parent executable/name/command,
hashes, `file.path`, `dll.path`, `registry.path` and IP fields are optional supporting
fields where the event type supplies them. User equality is not required across service
transitions. The JSON enumerates each contract and the specific Phase 6 field list.

### T1059.001 — PowerShell

Identity: **Execution**, Windows, ATT&CK technique version 1.5. PowerShell provides
command/script execution; observing the interpreter does not establish abuse.
[Official technique](https://attack.mitre.org/techniques/T1059/001/).

Primary telemetry: **Microsoft-Windows-Sysmon, event 1**, including executable, command,
actor GUID and ancestry. Sysmon 3/7/11/13 are optional supporting feeds; their presence
does not guarantee a match for a specific execution. The 1,726 encoded-or-bypass matches
are a broad argument locator, not a tuned detection or proof of encoded content.

Baseline concept: count distinct PowerShell process-creation event IDs. Stronger concept:
review argument structure, retrieval/execution intent and parent context, then seek a
separate child, file or network observation joined to the actor. Neither `Bypass` nor
an interpreter name alone justifies elevated confidence. Phase 6 needs the process
contract and parent name/command for contextual comparisons.

False-positive candidates include approved scripts, inventory and remote administration.
The retained process-inventory command has routine semantics, but its Public-directory
`splunkd.exe` parent remains suspicious; it is **not a clean benign control**. Missing
script-block logs, renamed executables, in-process .NET hosting, command escaping and
missing process records can cause false negatives. Correlation further depends on
separate supporting events.

### T1059.003 — Windows Command Shell

Identity: **Execution**, Windows, ATT&CK technique version 1.5. Shell and batch execution
expose arguments and ancestry suitable for a distinct process analytic.
[Official technique](https://attack.mitre.org/techniques/T1059/003/).

Primary telemetry: **Microsoft-Windows-Sysmon, event 1**. Baseline concept: count distinct
cmd.exe launches. Stronger concept: inspect service-origin or otherwise unusual parents
together with command intent and a separately observed descendant. `/c` alone remains
broad. Phase 6 additionally needs `process.parent.name`; GUID ancestry supports a shell
→ PowerShell or shell → service-control relationship.

Installers, batch jobs, directory changes and legitimate service wrappers are plausible
false positives. The directory-change example retains its ancestry so routine semantics
are not mistaken for verified benign intent. Renaming, missing arguments/parents, shell
metacharacter variants and absent child telemetry cause false negatives. Parent outliers
need an explicit local comparison scope; this is not a verified clean enterprise baseline.

### T1543.003 — Windows Service

Identity: **Persistence, Privilege Escalation**, Windows, ATT&CK technique version 1.6.
Creation/configuration can establish a service execution mechanism; it does not by itself
prove exploitation, startup success or durable persistence.
[Official technique](https://attack.mitre.org/techniques/T1543/003/).

Telemetry: **Service Control Manager 7045**, **Sysmon 1** for service-control commands,
and **Sysmon 13** for ImagePath modifications. Baseline concept: inventory 7045 records.
Keep the sc.exe create/configuration process and registry baselines separate. Stronger
concept: combine service command/path semantics, service-origin interpreters and
independent registry/process behaviour. Names, path rarity and SYSTEM execution alone
do not establish maliciousness.

Service-control processes need the shared process contract. Registry variants need
`registry.path`, actor process name/GUID and supporting value evidence where available.
Installation review also needs the **literal** keys
`_source.data.win.eventdata.serviceName` and `_source.data.win.eventdata.imagePath`
inside `windows_apt.original`. These are preserved in a disabled, **unindexed** object,
not searchable ECS fields usable directly in KQL/EQL joins. The shell/PowerShell GUID
pair is implementable with current ECS fields; automating the third installation-object
match requires a separately reviewed extraction approach later. No mapping changed here.

Defender driver installations and updater services provide plausible legitimate
comparisons. A Defender-looking path is not signature validation and could be imitated.
Missing installation records, API/PowerShell changes outside sc.exe, incomplete registry
telemetry and unindexed fields limit coverage. Requiring a shell would miss services
running ordinary binaries, so this must remain one supported service variant.

## Representative live evidence

These are source observations, never commands executed by this project. Full strings,
fields, source/row hashes and contextual labels are in the JSON. Rows below are zero-based
`source_row_index`, not physical CSV lines. Filenames are under
`dataset/raw/windows-apt-2025-v4/Windows-APT 2025 A Dataset for APT-Inspired Attack/`.

| Role | Exact `event.id` | UTC timestamp; host | Observed context; source file and row |
|---|---|---|---|
| PowerShell service descendant | `3faf8b4d35dd5fcb924ed44ed7e10d944f2b84243f9bf6f98c07b4e4b4d8d00d` | 2024-11-09T19:19:38.535734500Z; DESKTOP-FMI6MML | SYSTEM; hidden/no-profile PowerShell requests marker-file creation; `1-11-November.csv`, 8598 |
| PowerShell semantic comparison | `4ea94313bd0565c1a29ba059663e5824ebe4f2b9a7e25e1430f451017feef75c` | 2024-12-11T18:42:39.678206100Z; DESKTOP-QGB4EQH | mari; win32_process/get-process owner inventory with Bypass; suspicious parent retained; `11-12-December.csv`, 5838 |
| PowerShell retrieval command | `002f1cdedcb6eb7b3c38aa893f0dc17477349ec2cb8025809c7b2bacf5d73b8a` | 2024-12-02T23:08:01.013963900Z; DESKTOP-FMI6MML | maryam; Invoke-WebRequest targets a macro-enabled attachment in TEMP; intent only; `03-04-December.csv`, 2931 |
| Service-origin shell | `8f0564e44cea0da1038e46484c816a8668ee890529fcc83432f6c830a64d3e90` | 2024-11-09T19:19:38.522452Z; DESKTOP-FMI6MML | SYSTEM; cmd.exe parent services.exe, invokes PowerShell; `1-11-November.csv`, 8597 |
| Shell semantic comparison | `013759f2600917245402d8f22e97bde725d1262bdd8b0a6ec1ba03f28de52002` | 2024-12-02T22:15:58.975210700Z; DESKTOP-QGB4EQH | mari; directory change under the user profile; `03-04-December.csv`, 2777 |
| Shell with service-control child | `037eafabf296d88c5b73294c469b088fc55c9acd4c40d9844b62421efb34b56b` | 2024-12-03T12:23:06.459265100Z; DESKTOP-QGB4EQH | Retrieved parent of an sc.exe command; `03-04-December.csv`, 1475 |
| Installation associated with shell | `0213192542e4d0897f86e0572722fb228d413a313b3347a86eb62d6316e3a21f` | 2024-11-09T19:19:38.500914800Z; DESKTOP-FMI6MML | ARTService, LocalSystem, demand-start, matching full command; `1-11-November.csv`, 2714 |
| Installation comparison candidate | `0b1f6f98acb0185bf38e6311eff2d76c0f98da7c178dea8dbe3fecc074ab9f7e` | 2024-11-30T08:00:19.224659200Z; DESKTOP-FMI6MML | MpKsldc8590db driver, Defender Definition Updates path ending MpKslDrv.sys; `30-November.csv`, 102 |
| Service creation command | `01a39aaa0ab4f30ba0883fad92598d99a9347baed6a395936abbda41ae2bd09a` | 2024-12-10T10:50:27.384701800Z; DESKTOP-QGB4EQH | Sysmon records sc.exe create intent; `10-December-P1.csv`, 2426 |
| Service registry write | `0003471104182867c330e6864c1f64de47457d6924783197ac3467c026d3eaae` | 2024-12-09T05:56:59.810229200Z; DESKTOP-QGB4EQH | Sysmon 13 Services ImagePath write; `07-10-December.csv`, 7665 |

The PowerShell service descendant carries Account Discovery and Windows Command Shell
annotations despite its PowerShell executable. Its derived scenario differs from its
actual cmd parent. Neither co-labels nor scenario equality can define the behaviour or
replace the GUID relationship.

## ATT&CK, CAR and ATT&CK log-source table

Authoritative pages accessed **12 September 2026 UTC**. Current ATT&CK terminology is
used for selections; historical source labels remain unchanged. Guidance supplies
concepts, while observed telemetry determines implementable fields.

| Sub-technique | ATT&CK strategy / analytic and listed data components | Dataset provider / codes | Available ECS evidence | Evidence exists? |
|---|---|---|---|---|
| T1059.001 PowerShell | [DET0455 / AN1252](https://attack.mitre.org/detectionstrategies/DET0455/): Process Creation DC0032; Command Execution DC0064; Process Metadata DC0034; Module Load DC0016 | Microsoft-Windows-Sysmon **1**, optional **7**. Strategy-listed PowerShell 4103/4104/4105/4106 and 400/403 absent | event provider/code, host, process name/executable/command, actor/parent GUID; dll.path in module events | **Yes, process contract.** Native script-block/session visibility unavailable |
| T1059.003 Windows Command Shell | [DET0202 / AN0578](https://attack.mitre.org/detectionstrategies/DET0202/): Process Creation DC0032; Module Load DC0016; Script Execution DC0029 | Dataset Microsoft-Windows-Sysmon **1** supplies equivalent process creation. Strategy lists Security **4688**, which is absent; Sysmon **7** exists; EDR script-block feed absent | event provider/code, host, command/executable, parent name/command, actor/parent GUID | **Yes, equivalent process telemetry.** Do not claim Security 4688 or EDR coverage |
| T1543.003 Windows Service | [DET0552 / AN1527](https://attack.mitre.org/detectionstrategies/DET0552/): Service Creation DC0060; Process Creation DC0032; Windows Registry Key Modification DC0063; Driver Load DC0079 | **Service Control Manager 7045** supplies installation evidence; Microsoft-Windows-Sysmon **1, 13**. Strategy-listed Security **4697** and Sysmon **6, 14** absent | event provider/code, host; process fields for sc.exe/children; registry.path and actor GUID for writes; original service fields retrieved separately | **Yes, with object-search limitation.** SCM 7045 is an observed equivalent, not 4697 |

The service strategy motivates configuration/path and ancestry analysis; the shell
strategy motivates parent/argument context; PowerShell guidance motivates arguments
plus independent process/module/network evidence. These are adaptable concepts, not a
claim that every recommended log source exists.

| Verified CAR analytic | Application |
|---|---|
| [CAR-2014-04-003 Powershell Execution](https://car.mitre.org/analytics/CAR-2014-04-003/) | Process creation and parent context; interactive/noninteractive comparisons are not truth labels |
| [CAR-2014-11-002 Outlier Parents of Cmd](https://car.mitre.org/analytics/CAR-2014-11-002/) | Shell parent comparisons; historical baseline and thresholds need local measurement |
| [CAR-2014-05-002 Services launching Cmd](https://car.mitre.org/analytics/CAR-2014-05-002/) | Service-origin cmd concept observed in three documents; authorized tests remain possible |
| [CAR-2013-09-005 Service Outlier Executables](https://car.mitre.org/analytics/CAR-2013-09-005/) | Service executable/update comparisons; no clean 30-day baseline or copied historical pseudocode is claimed |

[Microsoft Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
supports event-specific process/GUID, module, file, registry and network interpretation.
Always check provider plus code: another provider's 4104 is not PowerShell logging.

Rejected candidates also have real guidance; corroboration gaps drive their rejection:

| Candidate | Verified reference and relevance |
|---|---|
| [Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) | [DET0441](https://attack.mitre.org/detectionstrategies/DET0441/) supports creation/change and process/file/registry evidence; [CAR-2013-08-001 Execution with schtasks](https://car.mitre.org/analytics/CAR-2013-08-001/) is directly relevant |
| [Bypass User Account Control](https://attack.mitre.org/techniques/T1548/002/) | [DET0388](https://attack.mitre.org/detectionstrategies/DET0388/) motivates registry, auto-elevation utilities and resulting process context |
| [File Deletion](https://attack.mitre.org/techniques/T1070/004/) | [DET0140](https://attack.mitre.org/detectionstrategies/DET0140/) motivates deletion observations, ancestry and post-execution context |
| [DLL](https://attack.mitre.org/techniques/T1574/001/) | [DET0201](https://attack.mitre.org/detectionstrategies/DET0201/) motivates file/load relationships beyond generic volume; DLL is the current T1574.001 name |
| [Compile After Delivery](https://attack.mitre.org/techniques/T1027/004/) | [DET0501](https://attack.mitre.org/detectionstrategies/DET0501/) motivates compilation followed by resulting executable behaviour |
| [Windows Remote Management](https://attack.mitre.org/techniques/T1021/006/) | [DET0477](https://attack.mitre.org/detectionstrategies/DET0477/) motivates network, remote-session and process context |

No direct CAR analytic is asserted for the other five rejected alternatives. Unrelated
identifiers are not used to fill a reference column.

## Verified correlation feasibility

Joining **20,814 actual Sysmon process-creation documents** gives these distinct ordered
pairs. Host/GUID spelling is case-folded; the parent's `process.entity_id` must equal
the child's `process.parent.entity_id`. Both records require explicit UTC time. Integer
nanoseconds, inclusive windows and distinct event IDs prevent time truncation and self
joins. No reused PID, source label or scenario is used.

| Direction | 60 seconds | 300 seconds | 900 seconds |
|---|---:|---:|---:|
| PowerShell → cmd.exe | 120 | 120 | 120 |
| cmd.exe → PowerShell | 261 | 261 | 261 |
| cmd.exe → sc.exe create/binPath-config command | 268 | 268 | 268 |

These are exploratory pairs, not alerts. Service commands require an observed create
token or config token plus binPath. Equal counts show observed sensitivity; they do not
prove that 60 seconds is an optimal production window.

The strongest relationship has **three independent records** on DESKTOP-FMI6MML:

1. SCM installation `0213192542e4d0897f86e0572722fb228d413a313b3347a86eb62d6316e3a21f`
   at **2024-11-09T19:19:38.500914800Z** records ARTService/LocalSystem and a full image
   command invoking cmd.exe, PowerShell and marker-file creation.
2. Shell `8f0564e44cea0da1038e46484c816a8668ee890529fcc83432f6c830a64d3e90`
   at **2024-11-09T19:19:38.522452Z** has parent services.exe and a full command matching
   the service image after Windows case/backslash comparison. Gap: **21,537,200 ns**.
3. PowerShell `3faf8b4d35dd5fcb924ed44ed7e10d944f2b84243f9bf6f98c07b4e4b4d8d00d`
   at **2024-11-09T19:19:38.535734500Z** has parent GUID
   **`{D8AF36FB-B5CA-672F-3502-000000000700}`**, exactly the shell actor GUID.
   Gap: **13,282,500 ns**. Total: **34,819,700 ns (0.0348197 s)**.

The saved evidence contains **three** such service → shell → PowerShell chains on three
hosts; other total spans are 0.020549 and 0.0418019 seconds. A full object command match
is stronger than host/time or basename matching, but case/backslash comparison is not
semantic command equivalence. SCM lacks a process GUID, so this is corroborated object
association, not a proven direct service API call chain. The searchable implementation
path is the two-event service-origin shell → PowerShell GUID pair. Full installation
confirmation remains retrieved evidence until reviewed extraction is implemented later.

Authorized service testing/administrative automation is plausible. The PowerShell command
requests an art-marker file; this chain does not prove file creation, malicious causality
or lasting persistence. Different derived scenarios across related records further rule
out scenario equality as a required join.

## Baseline versus correlation and dashboard plan

Baseline unit: distinct `event.id` per process/installation/registry cohort. Correlation
unit: distinct ordered tuple of supporting event IDs; later retain a deterministic
correlation ID. Also count distinct participating baseline events because one event can
support several pairs. Never call a sequence count divided by unrelated event sums accuracy.

Test **60 seconds** initially and **300/900 seconds** for sensitivity. Preserve order and
explicit time. An independent descendant or matching installation increases confidence
that a service invoked an interpreter chain; intent remains unknown. Keep standalone
candidates: requiring children can miss unlogged, delayed or single-process behaviour.
Alternative file/network support may recover visibility later, but reduced false negatives
have not been demonstrated. Lower alert volume does not establish lower false positives.

Dashboard planning: selected IDs/current tactics, clearly labelled event/sequence counts,
historical time, host, available user, ancestry GUIDs, commands, service/registry evidence
and provenance drill-down. Separate confidence in observed behaviour from severity and
unknown intent. Make absent fields and service-object search limits visible. Publisher
labels must not become independent malicious/benign verdicts.

## Reproduction and limitations

With the verified stack running, these commands read Elasticsearch and update local
analysis artifacts without regenerating data or installing analytics:

```powershell
.\.venv\Scripts\python.exe scripts/inspect_technique_candidates.py
.\.venv\Scripts\python.exe scripts/inspect_selection_relationships.py
.\.venv\Scripts\python.exe scripts/verify_technique_selection.py
```

Verification fails on changed Phase 2/3/4 hashes, count drift, missing/changed examples,
changed relationships or inconsistent selections. It replays every exploratory predicate
and recomputes relationships from freshly read process/installation records. Ignored
projection caches are reproducible intermediate files.

No independent event-level binary truth exists; no precision, recall, F1 or FPR is
calculated. Native PowerShell logging and several recommended Security/Sysmon event
types are absent. All 11,410 undated events remain available for standalone review and
are excluded from ordered correlation. Lab emulation, derived scenarios, escaping,
missing lineage and unindexed originals limit interpretation. See the
[limitations register](../docs/limitations.md).

Phase 6 should implement and validate the three individual baseline/behavioural
specifications against these contracts. Final correlation remains Phase 7. Neither phase
is started automatically by this selection record.
