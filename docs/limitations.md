# Limitations register

| Limitation | Implication | Required next action |
|---|---|---|
| scenario evaluation scope | Individual strategies/correlation replayed; bounded review and scenario demonstration complete; intent and accuracy remain unmeasured | The dashboard implements the validated evidence contract; retain candidate interpretation and explicit units |
| v4 mapping is derived; citation retains base v3 DOI | Contextual attribution is not independent technique truth | Retain v4 provenance and assess label derivation |
| Combined and period exports | Same document IDs but altered representations; concatenation double-counts | Use verified period corpus and retain combined comparison evidence |
| Field-name hints | Cannot establish source semantics | Review actual values and publisher documentation |
| Missing or malformed telemetry | Coverage and correlation may be incomplete | Preserve rejects and report field completeness |
| Partial, display and numeric timestamps | 11,410 events have no justified @timestamp and remain flagged | Preserve unresolved events; never substitute current ingestion time |
| Derived scenario assignments | Circular validation if used as independent technique truth | Report attribution strength; avoid unsupported accuracy metrics |
| Broad or co-labelled Wazuh rules | Routine DLL loads and commands can receive attack labels | Validate behaviour from telemetry and distinguish separate-event evidence |
| No independent event-level benign/malicious labels | Precision, recall and false-positive rates unsupported | Define a defensible evaluation unit and documented review protocol |
| Lab-generated source dataset | Limited external validity | Avoid claims about production effectiveness |
| Single local Elastic node | Limited capacity and resilience | Measure resource use; retain state and backups |
| Local HTTP browser endpoint | Intended only for host-local access | Keep loopback binding; review TLS before any wider deployment |
| Inspector samples/JSON limits | Report can be partial | Check `scan_complete`, errors and uninspected files |
| Zero process GUIDs | 60 source/parent GUID observations cannot identify a process | Original values retained; invalid normalized GUIDs omitted and flagged |
| Provider-dependent fields | Unreviewed contexts stay in original evidence | Extend mappings only after reviewing semantics and source examples |
| Unindexed original payloads | Preserved in `_source`; `event.original` and disabled evidence objects are not searchable | Use mapped ECS fields and retrieve originals for review |
| Original whitespace retained | Source space-filled cells increase NDJSON size | Keep evidence/schema sidecars together; assess storage before ingesting |
| Logstash timestamp serialization | Insignificant fractional trailing zeros can change; indexed nanoseconds match | Compare instants to nanoseconds and retain the exact source string |
| Local full-file replay | Container restart can replay the enabled input; stable IDs prevent count inflation | Use the wrapper and inspect current run metrics; no production replay guarantees |
| Scenario enrichment versus assignment | All events retain mapping context, but 5,905 have no assigned scenario ID | Compare attribution strengths as well as assigned IDs |
| Representative preservation checks | Thirteen categories cover eight source documents, not every indexed field value | Treat these as spot checks alongside full data normalization verification and live coverage counts |
| Local operational observations | Index size changes with segment merges, and duration includes container startup | Avoid scalability or benchmark claims |
| Selected interpreter baselines | 2,060 PowerShell and 7,717 shell launches include legitimate and ambiguous uses | Treat counts as candidate events; inspect arguments, ancestry and separate support |
| Service event units | 102 installations, 155 create commands, 117 configuration commands and 708 registry writes represent different observations | Keep denominators separate; neither sum nor equate them with unique operations/attacks |
| Service object search | serviceName/imagePath remain literal keys inside unindexed original evidence | Python validates fetched installation-object evidence; the executable indexed EQL rule remains the shell/PowerShell GUID pair |
| Missing recommended feeds | Native PowerShell logs, Security 4688/4697/4698/4702 and relevant task-registration corroboration are absent | Document provider-specific coverage; use observed equivalents and avoid claims of comprehensive technique coverage |
| Process/command intent | A command requests an action but does not prove its outcome | Seek independent file, installation or child-process events before claiming completion |
| Comparison evidence is uncertain | Routine inventory/directory-change semantics may coexist with suspicious ancestry; Defender-looking paths can be imitated | Retain full context and describe benign candidates, not known negatives |
| Exploratory joins | 120/261/268 exploratory pairs are broader than the selected final relationship and are observations, not alerts | Use the event correlation complete 261 broad / 3 refined pairs and scenario evaluation separate event/pair/triple review units |
| Correlation precision and coverage | Strong GUID joins need both process records; SCM object equality is an association, and broad Windows case/backslash comparison is not semantic command equivalence | Preserve exact strings, explicit UTC and all evidence IDs; report missing parents and keep standalone variants |
| Window sensitivity | Counts are unchanged at 60/300/900 seconds on this corpus | Do not claim an optimal window; test delayed and missing-event behaviour in later validation |
| Current versus historical ATT&CK | Current guidance/names may differ from publisher annotations | Record official URLs/access dates; retain original labels without silently rewriting them |
| Refined candidate volumes | PowerShell 2,060 → 290; shell 7,717 → 172; service create 155 → 41 and config 117 → 108 | Describe volume reduction only, not proven false-positive reduction |
| Command pattern coverage | Encoded-only, renamed/hosted interpreters, aliases, spacing, and quoted/commented text can cause missed or ambiguous matches | Preserve exact commands and missing-field counts; avoid interpreting substring matches as shell parsing |
| Service configuration concentration | 108 of 117 configuration events match the same interpreter-oriented command family | Explain the observed homogeneity; retention is not precision or prevalence |
| ES\|QL export cap | Each export is capped at 10,000 rows | Use the runner's full pre-limit count and fail on truncation; do not use an exported row count alone on larger corpora |
| Batched evidence readback | Elasticsearch rejects an ids query above its 10,000 result window | Read back at most 1,000 requested IDs per batch and verify every batch; retain cluster limits |
| KQL review filters | KQL files are broader than the refined regex predicates | Treat ES\|QL as authoritative and retain the explicit role in the manifest |
| Verification artifact continuity | Refreshing the original ingestion validation JSON changes a hash checked by technique selection | Save the individual detection prerequisite replay separately with --output-directory |

No incident reconstruction, automated response, generated attacks or unsupported
precision/recall claims are part of this implementation.

## Correlation-specific limits

- Exact tuple enumeration yields 261 broad and 3 refined pairs, not attack counts. Broad
  EQL returns 222 sequences and omits 39 fan-out pairings under sequence-state semantics.
- EQL requires a millisecond runtime date for this date_nanos index. A nanosecond
  tiebreaker and one-millisecond envelope support retrieval; Python enforces strict
  ordering and the exact inclusive historical window. Stored data/mappings are unchanged.
- All three earlier service triples validate and meet refined endpoints; none is an
  observed refinement exclusion. Removed encoded-only broad lineage remains a concrete
  coverage example, not a proven false negative.
- 287 refined PowerShell events lack this specific supporting pair; 169 refined shell
  events belong to the other service-control branch. These remain standalone candidates.
- 39 baseline PowerShell events lack usable parent GUIDs. Missing process events,
  alternate parents/interpreters, direct executables and delayed/unobserved service
  execution prevent otherwise plausible relationships.
- Service imagePath is unindexed source evidence. Case/backslash full-command comparison
  is lexical association, not command parsing or proof of service outcome/intent.

See [event correlation](event-correlation-validation.md) for executable queries, exact units and verified evidence.

## Evidence-review and dashboard limits

- The scenario evaluation set contains 11 deterministic units, not a random intent sample. Its five
  evidence categories describe structure; no class prevalence or error rates follow.
- The earliest SCM triple is selected by installation time, not apparent maliciousness.
  All three validate; no excluded triple is invented for the FN discussion.
- The primary 7045 event is an installation baseline, outside refined sc.exe create/config
  process cohorts. Source-image association does not identify a service API call.
- Standalone process GUID fields do not prove the parent was independently captured.
  SCM has no applicable process ancestry; its service account is not a process user.
- Dashboard rule names, analyst technique mappings, correlation IDs and review categories
  are local artifacts, not installed source-index fields. Snapshot metrics require clear
  historical scope; UI filters must not imply unimplemented tuple recomputation.
- The 611 activity rows are events within four refined cohorts; 16 reviewed events and
  18 preserved scenario records have separate scopes. No total is an attack count.

dashboard implementation installs these derived fields only in `attack-correlator-dashboard-v1`.
Its 881 documents present validated artifacts and source references; this is not
another detector or a new source of truth. Prerequisite hash drift, altered counts,
missing source IDs or changed evidence stop generation.

The dashboard retains a fixed 5 November–15 December 2024 UTC scope. Search/membership
filters affect the detection evidence table; overview and scenario panels stay fixed.
Exact aggregation filters preserve the six metrics;
chart queries use explicit historical bounds. Scenario/supporting Markdown panels are
generated snapshots. Explicit Discover cohort links include the full historical rule
query; additional ad hoc filters do not carry over. Kibana's built-in Open in Discover
can drop membership control state. Use the explicit links to reproduce KPI row sets.
Regenerate and validate after authorized analytics changes.

The export contains saved objects, not data or credentials. It needs the verified source
corpus and generated presentation index. Kibana can remap imported object IDs; validation
follows the returned destinations. An empty space already has a default settings object,
which the import replaces with UTC settings. This implementation is validated on Kibana
9.5.3; other versions need fresh API/import/render checks. Long displayed values wrap;
the stored source strings remain exact.

See [scenario evaluation](scenario-validation-and-evaluation.md), [dashboard implementation](kibana-dashboard-implementation.md) and the [dashboard guide](dashboard.md).
