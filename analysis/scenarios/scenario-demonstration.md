# Bounded scenario demonstration

Prerequisite replay: 2026-09-16T12:50:21.306930+00:00. Every displayed scenario and comparison was read back from live Elasticsearch.

## Selection and scope

Earliest validated triple by service-installation UTC nanoseconds; ties use the lexicographically sorted ordered event-ID tuple. Verify all three live before selection; fail on drift rather than silently substitute another scenario.

This is a bounded three-record relationship, not a complete incident chronology. No inferred intermediate events, attack execution or dashboard installation is included.

## Primary relationship

| Host | Ordered installation → shell → PowerShell event IDs | UTC timestamps | Gaps ns |
|---|---|---|---|
| DESKTOP-DS4FBF4 | `be75d1504e5784527dfd60bc35420d21f910b57ffba3ffcc1d84ec30c23070f9` → `c5a93a534cf031f5789b321d070b3f6cf33ec3e79e50b72cf15e384b7821e8e4` → `c87894aacb7c79e770e4eb8b1fd95fcf9612bb5fddba0c3f00edea3a9a9d6634` | 2024-11-06T09:58:51.208562600Z → 2024-11-06T09:58:51.235401Z → 2024-11-06T09:58:51.250364500Z | 26838400 + 14963500 |

Triple correlation ID: `f09a7676f6f7a5fea1aa767b84a4dbb50411cbdf1d66da690e98aa6a738ffa9c`. Total span: **41,801,900 ns**. All three events are explicitly timed and ordered within the 60-second window.

The installation's preserved imagePath and full shell command match after trimming outer whitespace, case folding and collapsing repeated backslashes. Exact strings are retained below and in JSON. This is lexical source association; disabled original fields are never used as indexed search predicates.

Shell actor GUID: `{8e11608b-3ddb-672b-1705-000000000500}`. Child parent GUID: `{8e11608b-3ddb-672b-1705-000000000500}`. Only GUID case is normalized for equality; host equality is exact.

| Record | ATT&CK sub-technique | Supported observation and rule membership |
|---|---|---|
| A | T1543.003 | SCM 7045 installation baseline; source-only service object; service_installation |
| B | T1059.003 | Sysmon 1 cmd.exe; services.exe parent; PowerShell command; shell_baseline, shell_refined, refined_guid_pair |
| C | T1059.001 | Sysmon 1 PowerShell; hidden + no profile + inline New-Item command; powershell_baseline, powershell_refined, refined_guid_pair |

The SCM 7045 observation is the T1543.003 **installation baseline**. It is outside the refined sc.exe create/config process sets. The shell and child independently meet their refined rules; together with the source-associated installation they support all three selected techniques without merging service cohorts.

### Primary source evidence

**A — `be75d1504e5784527dfd60bc35420d21f910b57ffba3ffcc1d84ec30c23070f9`**

Provider `Service Control Manager`, event `7045`, UTC `2024-11-06T09:58:51.208562600Z`, host `DESKTOP-DS4FBF4`. User: Unavailable; domain: Unavailable.

| Evidence field | Preserved value |
|---|---|
| original service serviceName | ARTService |
| original service imagePath | C:&#92;&#92;WINDOWS&#92;&#92;system32&#92;&#92;cmd.exe /c powershell.exe -nop -w hidden -command New-Item -ItemType File C:&#92;&#92;art-marker.txt |
| original service accountName | LocalSystem |
| original service serviceType | user mode service |
| original service startType | demand start |

Provenance: windows-apt-2025-v4/Windows-APT 2025 A Dataset for APT-Inspired Attack/1-11-November.csv; source row index **3560**; original ID `9tvpAJMBLF98WFwuwQMU`; original index `wazuh-alerts-4.x-2024.11.06`. Row SHA-256 `8a95eaa9e8e489cbb9862a86479e7512aedf164d5e1306e651c91c5365d9a973`. JSON retains the source-file digest, dataset version and remaining provenance.

**B — `c5a93a534cf031f5789b321d070b3f6cf33ec3e79e50b72cf15e384b7821e8e4`**

Provider `Microsoft-Windows-Sysmon`, event `1`, UTC `2024-11-06T09:58:51.235401Z`, host `DESKTOP-DS4FBF4`. User: SYSTEM; domain: NT AUTHORITY.

| Evidence field | Preserved value |
|---|---|
| process.name | cmd.exe |
| process.executable | C:&#92;&#92;Windows&#92;&#92;System32&#92;&#92;cmd.exe |
| process.command_line | C:&#92;&#92;WINDOWS&#92;&#92;system32&#92;&#92;cmd.exe /c powershell.exe -nop -w hidden -command New-Item -ItemType File C:&#92;&#92;art-marker.txt |
| process.entity_id | {8e11608b-3ddb-672b-1705-000000000500} |
| process.parent.name | services.exe |
| process.parent.entity_id | {8e11608b-0c94-672b-0a00-000000000500} |
| process.parent.command_line | C:&#92;&#92;WINDOWS&#92;&#92;system32&#92;&#92;services.exe |

Provenance: windows-apt-2025-v4/Windows-APT 2025 A Dataset for APT-Inspired Attack/1-11-November.csv; source row index **3559**; original ID `9dvpAJMBLF98WFwuwQMU`; original index `wazuh-alerts-4.x-2024.11.06`. Row SHA-256 `4173c4bdeea2b2d7feb00f3f3b324d5d313eb9d2e27a3f36c0c902176a27a38f`. JSON retains the source-file digest, dataset version and remaining provenance.

**C — `c87894aacb7c79e770e4eb8b1fd95fcf9612bb5fddba0c3f00edea3a9a9d6634`**

Provider `Microsoft-Windows-Sysmon`, event `1`, UTC `2024-11-06T09:58:51.250364500Z`, host `DESKTOP-DS4FBF4`. User: SYSTEM; domain: NT AUTHORITY.

| Evidence field | Preserved value |
|---|---|
| process.name | powershell.exe |
| process.executable | C:&#92;&#92;Windows&#92;&#92;System32&#92;&#92;WindowsPowerShell&#92;&#92;v1.0&#92;&#92;powershell.exe |
| process.command_line | powershell.exe  -nop -w hidden -command New-Item -ItemType File C:&#92;&#92;art-marker.txt |
| process.entity_id | {8e11608b-3ddb-672b-1805-000000000500} |
| process.parent.name | cmd.exe |
| process.parent.entity_id | {8e11608b-3ddb-672b-1705-000000000500} |
| process.parent.command_line | C:&#92;&#92;WINDOWS&#92;&#92;system32&#92;&#92;cmd.exe /c powershell.exe -nop -w hidden -command New-Item -ItemType File C:&#92;&#92;art-marker.txt |

Provenance: windows-apt-2025-v4/Windows-APT 2025 A Dataset for APT-Inspired Attack/1-11-November.csv; source row index **6798**; original ID `9NvpAJMBLF98WFwuwQMU`; original index `wazuh-alerts-4.x-2024.11.06`. Row SHA-256 `e76435fc1eec00450f0be3b0838de46d564546fa926f46a081929605147b490d`. JSON retains the source-file digest, dataset version and remaining provenance.

The service object is ARTService with LocalSystem account and demand start; the two process records identify NT AUTHORITY/SYSTEM. The command requests a marker file. These observations can represent an authorized test. They do not establish that the file was created, execution completed, persistence succeeded or the service survived.

## Corroborating relationships

| Host | Ordered installation → shell → PowerShell event IDs | UTC timestamps | Gaps ns |
|---|---|---|---|
| DESKTOP-FMI6MML | `0213192542e4d0897f86e0572722fb228d413a313b3347a86eb62d6316e3a21f` → `8f0564e44cea0da1038e46484c816a8668ee890529fcc83432f6c830a64d3e90` → `3faf8b4d35dd5fcb924ed44ed7e10d944f2b84243f9bf6f98c07b4e4b4d8d00d` | 2024-11-09T19:19:38.500914800Z → 2024-11-09T19:19:38.522452Z → 2024-11-09T19:19:38.535734500Z | 21537200 + 13282500 |
| DESKTOP-QGB4EQH | `a92fd759d8b04d9161da5913fd5d56098415fad9f482fc94a1b4ff392f76232a` → `3154fbb47b3c3efd78fe60f5d197b960a91a267fc38c8db272196e38c200c358` → `e46b3e7a7b6f86a51ec757effeaf49ae2ce8438f9223cad86ed6a00f5d7e4aea` | 2024-11-25T23:07:50.012425300Z → 2024-11-25T23:07:50.027718700Z → 2024-11-25T23:07:50.032974300Z | 15293400 + 5255600 |

- **DESKTOP-FMI6MML**: shell GUID `{D8AF36FB-B5CA-672F-3502-000000000700}` equals child parent GUID `{D8AF36FB-B5CA-672F-3502-000000000700}` after case-only comparison. Full service-image/shell command association, ordering, source provenance and both refined endpoints pass. Triple ID `65c305042ffebd17a2627fe4b4a0b20ef5b75ae7bae09b12dc5b7887fc47c91d`.

- **DESKTOP-QGB4EQH**: shell GUID `{15959494-0346-6745-5B05-000000000500}` equals child parent GUID `{15959494-0346-6745-5B05-000000000500}` after case-only comparison. Full service-image/shell command association, ordering, source provenance and both refined endpoints pass. Triple ID `2f651454f30296c77fa573c1f4225fe7828571ff77c136516256d3c2189f2941`.

All three relationships validate on three hosts; none is excluded by refinement. The two later triples are corroboration, not additional incident narratives.

## Deterministic evidence review

Primary triple; the other two refined pairs; lexicographically first excluded broad pair; lowest event.id from each nonempty standalone refined PowerShell / other shell branch set; all pre-existing individual detection comparison IDs sorted by ID. No intent-based ranking.

Categories describe evidence structure and are not malicious/benign labels. Complete per-unit behaviour, membership, time/GUID/provenance completeness, legitimate explanation, uncertainty and coverage limits are in [scenario JSON](scenario-demonstration.json).

| Review role / unit | Ordered IDs | Category | Inclusion or exclusion |
|---|---|---|---|
| primary / ordered_triple | `be75d1504e5784527dfd60bc35420d21f910b57ffba3ffcc1d84ec30c23070f9` → `c5a93a534cf031f5789b321d070b3f6cf33ec3e79e50b72cf15e384b7821e8e4` → `c87894aacb7c79e770e4eb8b1fd95fcf9612bb5fddba0c3f00edea3a9a9d6634` | three_event_corroborated_candidate | SCM installation baseline plus refined shell and PowerShell; source image association and exact GUID ancestry corroborate three independent records. The 7045 event is outside both refined sc.exe process cohorts. |
| other_refined_pair / ordered_pair | `3154fbb47b3c3efd78fe60f5d197b960a91a267fc38c8db272196e38c200c358` → `e46b3e7a7b6f86a51ec757effeaf49ae2ce8438f9223cad86ed6a00f5d7e4aea` | strong_structural_correlation | Both refined endpoints and exact host/GUID/order/window pass; the associated installation is retained as corroboration. |
| other_refined_pair / ordered_pair | `8f0564e44cea0da1038e46484c816a8668ee890529fcc83432f6c830a64d3e90` → `3faf8b4d35dd5fcb924ed44ed7e10d944f2b84243f9bf6f98c07b4e4b4d8d00d` | strong_structural_correlation | Both refined endpoints and exact host/GUID/order/window pass; the associated installation is retained as corroboration. |
| excluded_broad_pair / ordered_pair | `01ea2e887c88adf9d4b6a5edf353af461617e8372ebfe98f63b117460e79b760` → `32be01ebebaa05d0b83cb068bbcab36b41c24a1a48ca750d33bed090f68bb51a` | broad_lineage_excluded_by_refinement | shell&#95;not&#95;in&#95;phase6&#95;service&#95;origin&#95;branch; powershell&#95;not&#95;in&#95;phase6&#95;refined&#95;set |
| standalone_powershell / event | `0139e7fcfc5b9bffc583128a7d46c35f829d2c075cd365dd94c606ba7d04ff81` | standalone_behavioral_candidate | Refined retrieval/execution behaviour passes; no required service-origin refined pair contains this event. |
| other_shell_branch / event | `047897958bacb22c374a7cd75e00d1ff4d497cf10a2c562dde718589d51006ca` | standalone_behavioral_candidate | Refined service-control/interpreter binPath branch passes; service-origin execution branch does not. |
| phase6_comparison / event | `013759f2600917245402d8f22e97bde725d1262bdd8b0a6ec1ba03f28de52002` | routine_or_ambiguous_comparison | Directory-changing shell command has a routine explanation. Retain ancestry; not independently certified benign. |
| phase6_comparison / event | `0487faae790fdea3e8ddbe6d23a87a7cd485da163032b1e9b4a5959adff6f555` | routine_or_ambiguous_comparison | Creation of an AtomicTestService&#95;CMD executable service is excluded because the configured binary is not an interpreter. This illustrates a coverage gap, not a benign verdict. |
| phase6_comparison / event | `078a375e7354cdc8386ff93052945d498573e06a1f989587a7e6368899b659ff` | routine_or_ambiguous_comparison | sc config Fax assigns fxssvc.exe, consistent with restoring a service binary. Context/authorization is unverified. |
| phase6_comparison / event | `0b1f6f98acb0185bf38e6311eff2d76c0f98da7c178dea8dbe3fecc074ab9f7e` | routine_or_ambiguous_comparison | SCM installation uses a Defender Definition Updates driver path. Plausible legitimate update; path appearance is not signature or trust verification. |
| phase6_comparison / event | `4ea94313bd0565c1a29ba059663e5824ebe4f2b9a7e25e1430f451017feef75c` | routine_or_ambiguous_comparison | Process inventory with Bypass has routine command semantics; its Public-directory splunkd.exe parent remains suspicious. Ambiguous comparison, not a known benign event. |

## Reproduction and limits

```powershell
.\.venv\Scripts\python.exe scripts/build_scenario_evidence.py
```

The default helper replays individual detection and event correlation, then verifies source evidence. `--reuse-validated-prerequisites` skips replay only after all saved hashes/counts pass; it still checks live counts, mapping, selected sources and both scenario queries. Fixed prerequisite/source inputs produce byte-identical outputs.

Use [exact scenario ES|QL](primary-scenario.esql) for indexed fields and [search request](primary-scenario-search.json) with `POST /windows-apt-events-*/_search` to retrieve the source-only service fields. These are evidence-retrieval queries after detection, not new detection rules.

- Evidence-strength categories describe structure, never malicious/benign ground truth.
- Wazuh annotations, publisher success ratios and scenario mappings/names are not independent truth and are not predicates or selection keys. They are omitted from these artifacts.
- This small deterministic review set is illustrative, not a random or representative sample of intent; it cannot estimate population error rates.
- No service survival, successful persistence, completed command, requested file creation or malicious intent is established. No intermediate events are inferred.
- SCM imagePath is source-only evidence. Case/backslash full-command normalization is lexical association, not Windows command parsing, service API identity or proof of causality.
- Missing Sysmon events, actor/parent GUIDs or valid UTC timestamps can prevent correlation.
- Other PowerShell parents, renamed or in-process PowerShell, direct service executables, other interpreters and delays beyond the window can evade the required structure.
- Narrow command predicates omit some technique-consistent activity. Exclusion does not establish benignness or a confirmed false negative; keep standalone detections visible.
- The 60/300/900-second results describe this corpus, not an optimal production window. The 11,410 undated observations cannot enter ordered correlation.
