# Detection and correlation evidence review

Prerequisite replay: 2026-09-16T12:50:21.306930+00:00. Live corpus: **102,011 total / 90,601 timed / 11,410 undated**.

## Units and review composition

- **event**: One distinct event.id within the named observation cohort.
- **ordered_pair**: [shell_event_id, powershell_event_id], distinct ordered IDs.
- **ordered_triple**: [service_installation_event_id, shell_event_id, powershell_event_id].

Review set: **11 units / 16 unique events**. Counts below describe review composition, not attack counts or intent prevalence. The two corroborating installation records are additionally retained in the scenario artifact, outside the other-pair review units.

| Unit type | Count |
|---|---:|
| event | 7 |
| ordered_pair | 3 |
| ordered_triple | 1 |

| Evidence-structure category | Reviewed units |
|---|---:|
| broad_lineage_excluded_by_refinement | 1 |
| routine_or_ambiguous_comparison | 5 |
| standalone_behavioral_candidate | 2 |
| strong_structural_correlation | 2 |
| three_event_corroborated_candidate | 1 |

Primary triple; the other two refined pairs; lexicographically first excluded broad pair; lowest event.id from each nonempty standalone refined PowerShell / other shell branch set; all pre-existing individual detection comparison IDs sorted by ID. No intent-based ranking.

## Full-corpus detection and correlation counts

| Individual cohort | Distinct events | Hosts | Historical UTC range |
|---|---:|---:|---|
| powershell_baseline | 2060 | 3 | 2024-11-05T10:42:56.3186326Z → 2024-12-22T09:13:51.694757Z |
| powershell_refined | 290 | 3 | 2024-11-05T11:03:49.493885Z → 2024-12-15T13:42:34.2637507Z |
| shell_baseline | 7717 | 3 | 2024-11-05T10:48:57.8075783Z → 2024-12-22T12:53:50.1888457Z |
| shell_refined | 172 | 3 | 2024-11-05T13:34:51.2080098Z → 2024-12-14T17:30:59.5689515Z |
| service_installation | 102 | 4 | 2024-11-05T10:54:14.4669595Z → 2024-12-22T11:05:33.0936847Z |
| service_create_baseline | 155 | 3 | 2024-11-05T13:35:33.3145881Z → 2024-12-14T09:01:47.5042143Z |
| service_create_refined | 41 | 3 | 2024-11-06T09:58:51.2110964Z → 2024-12-13T00:13:35.9641019Z |
| service_config_baseline | 117 | 3 | 2024-11-05T13:34:51.2709569Z → 2024-12-14T17:30:59.7729986Z |
| service_config_refined | 108 | 3 | 2024-11-05T13:34:51.2709569Z → 2024-12-14T17:30:59.7729986Z |
| service_registry | 708 | 3 | 2024-11-05T10:39:32.6261111Z → 2024-12-22T12:53:49.226296Z |

SCM installation, sc.exe create/config and registry observations remain separate cohorts. They are not summed into service operations or attacks.

| Window | Broad pairs / events / hosts | Refined pairs / events / hosts | Corroborated triples / events / hosts |
|---|---|---|---|
| 60s | 261 / 483 / 3 | 3 / 6 / 3 | 3 / 9 / 3 |
| 300s | 261 / 483 / 3 | 3 / 6 / 3 | 3 / 9 / 3 |
| 900s | 261 / 483 / 3 | 3 / 6 / 3 | 3 / 9 / 3 |

The additional behavioural and ancestry requirements reduced the candidate sequence volume from **261 broad lineage tuples to 3 strongly correlated tuples**. Broad and refined comparisons already share the same exact ancestry/time structure; the difference specifically adds service-origin shell and refined PowerShell behaviour. This is candidate-volume reduction, not measured false-positive reduction.

The broad EQL view yields 222 sequences, omitting 39 fan-out pairs. The complete deterministic event correlation validator supplies the 261-pair denominator. Counts remain unchanged over the three tested windows; production optimality is unmeasured.

## Primary and corroborating scenarios

The earliest installation is on **DESKTOP-DS4FBF4**, `2024-11-06T09:58:51.208562600Z`. All three selected techniques are evidenced; the SCM record is a baseline installation, not a refined sc.exe observation. Both later triples pass the same source-image/host/GUID/order checks. None is excluded. See [scenario demonstration](../scenarios/scenario-demonstration.md) for exact IDs, source values and gaps.

## Review findings and rubric

**primary — ordered_triple — three_event_corroborated_candidate**

IDs: `be75d1504e5784527dfd60bc35420d21f910b57ffba3ffcc1d84ec30c23070f9` → `c5a93a534cf031f5789b321d070b3f6cf33ec3e79e50b72cf15e384b7821e8e4` → `c87894aacb7c79e770e4eb8b1fd95fcf9612bb5fddba0c3f00edea3a9a9d6634`. Techniques: T1059.001, T1059.003, T1543.003.

SCM installation baseline plus refined shell and PowerShell; source image association and exact GUID ancestry corroborate three independent records. The 7045 event is outside both refined sc.exe process cohorts.

Completeness: explicit timestamps=True; provenance=True; process actor/parent GUIDs=True. GUID presence in a standalone record is not an independently observed parent. SCM object linkage uses source-image association, not an absent SCM process GUID.

Plausible authorized explanation: Authorized ARTService marker-file test or administrative service wrapper; the observed New-Item request does not prove the file was created.

Uncertainty: Authorization, intent and outcome are unverified. Evidence structure is not an independently adjudicated intent label. Coverage: Missing events/GUIDs/times, other parents/interpreters, direct executables, delays and narrow command rules can omit activity. A standalone record does not verify a separate parent event.

**other_refined_pair — ordered_pair — strong_structural_correlation**

IDs: `3154fbb47b3c3efd78fe60f5d197b960a91a267fc38c8db272196e38c200c358` → `e46b3e7a7b6f86a51ec757effeaf49ae2ce8438f9223cad86ed6a00f5d7e4aea`. Techniques: T1059.001, T1059.003.

Both refined endpoints and exact host/GUID/order/window pass; the associated installation is retained as corroboration.

Completeness: explicit timestamps=True; provenance=True; process actor/parent GUIDs=True. GUID presence in a standalone record is not an independently observed parent. SCM object linkage uses source-image association, not an absent SCM process GUID.

Plausible authorized explanation: Authorized marker-file test or service wrapper can match.

Uncertainty: Authorization, intent and outcome are unverified. Evidence structure is not an independently adjudicated intent label. Coverage: Missing events/GUIDs/times, other parents/interpreters, direct executables, delays and narrow command rules can omit activity. A standalone record does not verify a separate parent event.

**other_refined_pair — ordered_pair — strong_structural_correlation**

IDs: `8f0564e44cea0da1038e46484c816a8668ee890529fcc83432f6c830a64d3e90` → `3faf8b4d35dd5fcb924ed44ed7e10d944f2b84243f9bf6f98c07b4e4b4d8d00d`. Techniques: T1059.001, T1059.003.

Both refined endpoints and exact host/GUID/order/window pass; the associated installation is retained as corroboration.

Completeness: explicit timestamps=True; provenance=True; process actor/parent GUIDs=True. GUID presence in a standalone record is not an independently observed parent. SCM object linkage uses source-image association, not an absent SCM process GUID.

Plausible authorized explanation: Authorized marker-file test or service wrapper can match.

Uncertainty: Authorization, intent and outcome are unverified. Evidence structure is not an independently adjudicated intent label. Coverage: Missing events/GUIDs/times, other parents/interpreters, direct executables, delays and narrow command rules can omit activity. A standalone record does not verify a separate parent event.

**excluded_broad_pair — ordered_pair — broad_lineage_excluded_by_refinement**

IDs: `01ea2e887c88adf9d4b6a5edf353af461617e8372ebfe98f63b117460e79b760` → `32be01ebebaa05d0b83cb068bbcab36b41c24a1a48ca750d33bed090f68bb51a`. Techniques: T1059.001, T1059.003.

shell_not_in_phase6_service_origin_branch; powershell_not_in_phase6_refined_set

Completeness: explicit timestamps=True; provenance=True; process actor/parent GUIDs=True. GUID presence in a standalone record is not an independently observed parent. SCM object linkage uses source-image association, not an absent SCM process GUID.

Plausible authorized explanation: Encoded commands can implement approved automation or testing; encoding alone does not establish intent.

Uncertainty: Authorization, intent and outcome are unverified. Evidence structure is not an independently adjudicated intent label. Coverage: Missing events/GUIDs/times, other parents/interpreters, direct executables, delays and narrow command rules can omit activity. A standalone record does not verify a separate parent event.

**standalone_powershell — event — standalone_behavioral_candidate**

IDs: `0139e7fcfc5b9bffc583128a7d46c35f829d2c075cd365dd94c606ba7d04ff81`. Techniques: T1059.001.

Refined retrieval/execution behaviour passes; no required service-origin refined pair contains this event.

Completeness: explicit timestamps=True; provenance=True; process actor/parent GUIDs=True. GUID presence in a standalone record is not an independently observed parent. SCM object linkage uses source-image association, not an absent SCM process GUID.

Plausible authorized explanation: Approved retrieval/execution or security testing is possible; Public-directory splunkd.exe ancestry requires review.

Uncertainty: Authorization, intent and outcome are unverified. Evidence structure is not an independently adjudicated intent label. Coverage: Missing events/GUIDs/times, other parents/interpreters, direct executables, delays and narrow command rules can omit activity. A standalone record does not verify a separate parent event.

**other_shell_branch — event — standalone_behavioral_candidate**

IDs: `047897958bacb22c374a7cd75e00d1ff4d497cf10a2c562dde718589d51006ca`. Techniques: T1059.003.

Refined service-control/interpreter binPath branch passes; service-origin execution branch does not.

Completeness: explicit timestamps=True; provenance=True; process actor/parent GUIDs=True. GUID presence in a standalone record is not an independently observed parent. SCM object linkage uses source-image association, not an absent SCM process GUID.

Plausible authorized explanation: Authorized Fax-service configuration/testing is possible; the command's test wording is not independent truth.

Uncertainty: Authorization, intent and outcome are unverified. Evidence structure is not an independently adjudicated intent label. Coverage: Missing events/GUIDs/times, other parents/interpreters, direct executables, delays and narrow command rules can omit activity. A standalone record does not verify a separate parent event.

**phase6_comparison — event — routine_or_ambiguous_comparison**

IDs: `013759f2600917245402d8f22e97bde725d1262bdd8b0a6ec1ba03f28de52002`. Techniques: T1059.003.

Directory-changing shell command has a routine explanation. Retain ancestry; not independently certified benign.

Completeness: explicit timestamps=True; provenance=True; process actor/parent GUIDs=True. GUID presence in a standalone record is not an independently observed parent. SCM object linkage uses source-image association, not an absent SCM process GUID.

Plausible authorized explanation: Directory-changing shell command has a routine explanation. Retain ancestry; not independently certified benign.

Uncertainty: Authorization, intent and outcome are unverified. Evidence structure is not an independently adjudicated intent label. Coverage: Missing events/GUIDs/times, other parents/interpreters, direct executables, delays and narrow command rules can omit activity. A standalone record does not verify a separate parent event.

**phase6_comparison — event — routine_or_ambiguous_comparison**

IDs: `0487faae790fdea3e8ddbe6d23a87a7cd485da163032b1e9b4a5959adff6f555`. Techniques: T1543.003.

Creation of an AtomicTestService_CMD executable service is excluded because the configured binary is not an interpreter. This illustrates a coverage gap, not a benign verdict.

Completeness: explicit timestamps=True; provenance=True; process actor/parent GUIDs=True. GUID presence in a standalone record is not an independently observed parent. SCM object linkage uses source-image association, not an absent SCM process GUID.

Plausible authorized explanation: Creation of an AtomicTestService_CMD executable service is excluded because the configured binary is not an interpreter. This illustrates a coverage gap, not a benign verdict.

Uncertainty: Authorization, intent and outcome are unverified. Evidence structure is not an independently adjudicated intent label. Coverage: Missing events/GUIDs/times, other parents/interpreters, direct executables, delays and narrow command rules can omit activity. A standalone record does not verify a separate parent event.

**phase6_comparison — event — routine_or_ambiguous_comparison**

IDs: `078a375e7354cdc8386ff93052945d498573e06a1f989587a7e6368899b659ff`. Techniques: T1543.003.

sc config Fax assigns fxssvc.exe, consistent with restoring a service binary. Context/authorization is unverified.

Completeness: explicit timestamps=True; provenance=True; process actor/parent GUIDs=True. GUID presence in a standalone record is not an independently observed parent. SCM object linkage uses source-image association, not an absent SCM process GUID.

Plausible authorized explanation: sc config Fax assigns fxssvc.exe, consistent with restoring a service binary. Context/authorization is unverified.

Uncertainty: Authorization, intent and outcome are unverified. Evidence structure is not an independently adjudicated intent label. Coverage: Missing events/GUIDs/times, other parents/interpreters, direct executables, delays and narrow command rules can omit activity. A standalone record does not verify a separate parent event.

**phase6_comparison — event — routine_or_ambiguous_comparison**

IDs: `0b1f6f98acb0185bf38e6311eff2d76c0f98da7c178dea8dbe3fecc074ab9f7e`. Techniques: T1543.003.

SCM installation uses a Defender Definition Updates driver path. Plausible legitimate update; path appearance is not signature or trust verification.

Completeness: explicit timestamps=True; provenance=True; process actor/parent GUIDs=not applicable to SCM. GUID presence in a standalone record is not an independently observed parent. SCM object linkage uses source-image association, not an absent SCM process GUID.

Plausible authorized explanation: SCM installation uses a Defender Definition Updates driver path. Plausible legitimate update; path appearance is not signature or trust verification.

Uncertainty: Authorization, intent and outcome are unverified. Evidence structure is not an independently adjudicated intent label. Coverage: Missing events/GUIDs/times, other parents/interpreters, direct executables, delays and narrow command rules can omit activity. A standalone record does not verify a separate parent event.

**phase6_comparison — event — routine_or_ambiguous_comparison**

IDs: `4ea94313bd0565c1a29ba059663e5824ebe4f2b9a7e25e1430f451017feef75c`. Techniques: T1059.001.

Process inventory with Bypass has routine command semantics; its Public-directory splunkd.exe parent remains suspicious. Ambiguous comparison, not a known benign event.

Completeness: explicit timestamps=True; provenance=True; process actor/parent GUIDs=True. GUID presence in a standalone record is not an independently observed parent. SCM object linkage uses source-image association, not an absent SCM process GUID.

Plausible authorized explanation: Process inventory with Bypass has routine command semantics; its Public-directory splunkd.exe parent remains suspicious. Ambiguous comparison, not a known benign event.

Uncertainty: Authorization, intent and outcome are unverified. Evidence structure is not an independently adjudicated intent label. Coverage: Missing events/GUIDs/times, other parents/interpreters, direct executables, delays and narrow command rules can omit activity. A standalone record does not verify a separate parent event.

## FP/FN reasoning and ground truth

cmd.exe, PowerShell and service installation each have common administrative uses. Exact independently observed ancestry, service-origin context, ordering and refined behaviour make a much narrower candidate set. Authorized marker-file tests and service wrappers can still satisfy all conditions. Routine-looking inventory, directory and service commands remain ambiguous once parent context and unverified authorization are considered.

The removed encoded-only child has real cmd ancestry but lacks the refined PowerShell conditions; its shell also lacks the required service-origin branch. No encoded payload is decoded or executed. Missing support and alternate execution paths can hide valid technique activity. Standalone refined PowerShell and other-branch shell candidates remain visible; absence from a correlation is not a benign verdict.

- refined_powershell_without_service_origin_shell_tuple: **287 distinct events**.
- refined_shell_in_other_service_control_branch: **169 distinct events**.
- service_origin_shell_without_refined_child: **0 distinct events**.

Correlation supplements individual detection. A missing required relationship does not make a standalone candidate benign. The deterministic review is not a statistical sample and has no independent intent adjudication; no precision, recall, F1, false-positive rate, confusion matrix or numeric confidence is calculated.

## Dashboard evidence prepared

The four refined cohorts have **611 activity rows**, each carrying exact UTC time, event.id, observed host, rule name and an analyst-derived technique mapping. Per-rule daily UTC totals are retained. They are event observations within named cohorts, not a cross-technique attack count.

Overview refined counts: powershell_refined=290, shell_refined=172, service_create_refined=41, service_config_refined=108; refined correlation=3 pairs / 6 events / 3 hosts. Primary scenario=1 triple / 3 events / 1 host. Installation corroboration=3 triples / 9 events / 3 hosts.

[Dashboard contract](dashboard-contract.json) gives exact sources and filter semantics. [Dashboard documentation](../../docs/dashboard.md) identifies the required panels and verification gates. Source event IDs and timestamps are queryable; correlation IDs, review categories and analyst technique mappings are derived artifacts, not installed source-index fields. No malicious/benign, severity/confidence or forced network panel is supported. No dashboard is built/exported.

## Reproduction and live checks

```powershell
.\.venv\Scripts\python.exe scripts/build_scenario_evidence.py
.\.venv\Scripts\python.exe -m pytest -q --basetemp .test-tmp/evaluation
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m pip check
```

The helper verified **621 live event IDs**, individual detection and event correlation artifact/query hashes and count contracts, unchanged mapping and live corpus counts, all three triples, every reviewed unit and all four refined activity cohorts. Both exact-ID scenario ES|QL and source search returned the same ordered records and fields. The JSON records input/output/query/source-projection hashes. Fixed inputs produce identical output bytes; a prerequisite replay refreshes validation timestamps and therefore changes the recorded evidence snapshot hash.

- Evidence-strength categories describe structure, never malicious/benign ground truth.
- Wazuh annotations, publisher success ratios and scenario mappings/names are not independent truth and are not predicates or selection keys. They are omitted from these artifacts.
- This small deterministic review set is illustrative, not a random or representative sample of intent; it cannot estimate population error rates.
- No service survival, successful persistence, completed command, requested file creation or malicious intent is established. No intermediate events are inferred.
- SCM imagePath is source-only evidence. Case/backslash full-command normalization is lexical association, not Windows command parsing, service API identity or proof of causality.
- Missing Sysmon events, actor/parent GUIDs or valid UTC timestamps can prevent correlation.
- Other PowerShell parents, renamed or in-process PowerShell, direct service executables, other interpreters and delays beyond the window can evade the required structure.
- Narrow command predicates omit some technique-consistent activity. Exclusion does not establish benignness or a confirmed false negative; keep standalone detections visible.
- The 60/300/900-second results describe this corpus, not an optimal production window. The 11,410 undated observations cannot enter ordered correlation.

The implemented Kibana dashboard uses this contract with validated metrics, historical filters, evidence links and exported/imported saved objects. See ../../docs/kibana-dashboard-implementation.md.
