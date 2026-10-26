# Evaluation preparation

Status: **scenario evaluation bounded review and scenario demonstration complete**. Individual
detections and correlation were replayed; exact sources and dashboard inputs are verified.
Intent classification and measured accuracy remain unavailable. The dataset's Wazuh annotations,
publisher success ratios and derived scenario assignments are not independent event-level
malicious/benign truth. They cannot supply a confusion matrix for these rules.

## Units and observed counts

Standalone detection unit: **distinct event.id** within the named observation cohort.
Correlation unit: **ordered tuple of distinct event IDs**. Report participating events
separately; one shell can belong to multiple tuples. Do not divide event counts by tuple
counts and call the result an accuracy metric.

| Individual observation | Broad baseline events | Refined events |
|---|---:|---:|
| T1059.001 PowerShell process creation | 2,060 | 290 |
| T1059.003 Windows Command Shell process creation | 7,717 | 172 |
| T1543.003 SCM 7045 installation | 102 | Separate process variants below |
| T1543.003 sc.exe service creation command | 155 | 41 |
| T1543.003 sc.exe binPath configuration command | 117 | 108 |
| T1543.003 Services ImagePath registry write | 708 | Supporting baseline only |

| Correlation observation | Ordered tuples at 60 / 300 / 900s | Unique participating events | Hosts |
|---|---|---:|---:|
| Broad cmd → PowerShell GUID lineage | 261 / 261 / 261 | 483 (222 shells + 261 children) | 3 |
| Refined service-origin shell → refined PowerShell | 3 / 3 / 3 | 6 (3 shells + 3 children) | 3 |
| Separately corroborated installation → shell → PowerShell | 3 / 3 / 3 | 9 | 3 |

Broad lineage has twenty shells participating in multiple tuples (maximum three).
EQL's broad view returns 222 sequences and omits 39 fan-out pairings; the authoritative
complete join counts 261. Refined EQL and exact validation both return three. These are
language/relationship differences, not false positives or false negatives.

The individual and correlation counts come from [individual detection results](../analysis/detections/detection-results.json)
and [event correlation results](../analysis/correlation/correlation-results.json). The corpus remains
102,011 events, of which 90,601 have valid event time. Only explicit UTC endpoints can
enter ordered correlation; the other 11,410 events remain undated.

## Qualitative FP/FN assessment

- False-positive candidates: authorized service wrappers, marker-file tests, approved
  automation and routine administrative installations. A real installation and two
  GUID-linked process observations strengthen structure without proving malicious intent.
- False-negative candidates: removed broad pairs with encoded-only PowerShell; legitimate
  technique activity outside individual detection's argument predicates; missing events/GUIDs/time;
  delayed or alternate-parent/interpreter execution. These are coverage examples, not
  verified malicious misses. Thirty-nine baseline PowerShell events lack a usable parent GUID.
- All three previously known service triples validate and satisfy the refined endpoints.
  No known triple was excluded. The rule does leave 287 refined PowerShell records without
  the required service-origin pair and 169 shell candidates in the other service-control
  branch. Missing support for this narrow relationship does not establish a negative verdict.
- Candidate sequence volume is reduced by 258 tuples (261 → 3). No independent truth
  supports presenting that change as a false-positive reduction.

| Accuracy measurement | Status | Evidence needed |
|---|---|---|
| Precision | Unavailable | Independently adjudicated matching tuples and a TP/FP policy |
| Recall | Unavailable | Defensible expected positives and observation/coverage scope |
| F1 | Unavailable | Valid precision and recall on the same unit |
| False-positive rate | Unavailable | Reliable negatives and a defined TN denominator |
| Confusion matrix | Not produced | Independent labels, unit, exclusions and adjudication |

Software tests verify query/validator behaviour, not detector accuracy. Keep structural
strength categories separate from malicious intent and severity; no numeric risk score
is assigned. Full commands, provenance, joins, gaps, representative excluded pairs and
fan-out examples are retained for review.

## Bounded review and demonstration

The [scenario evaluation review](../analysis/evaluation/evaluation-report.md) uses **11 units**: seven
individual observations, three ordered pairs and one ordered triple, covering **16 unique
reviewed events**. All five structure categories are represented: standalone behavioural,
strong structural correlation, three-event corroborated, broad lineage excluded by
refinement, and routine/ambiguous comparison. These are not intent labels or population
class proportions. Every unit records behaviour, structure, time/GUID/provenance completeness,
inclusion/exclusion, plausible legitimate use, uncertainty and coverage limitations.

The primary triple is the earliest verified SCM installation by UTC nanoseconds (ordered
IDs break ties): **DESKTOP-DS4FBF4, 2024-11-06T09:58:51.208562600Z**. Gaps are **26,838,400
and 14,963,500 ns**. Its service object is a baseline SCM installation, outside refined
sc.exe process cohorts. Both interpreter endpoints are refined. The other two triples
validate on two other hosts; no known triple is excluded. Full details are in the
[scenario demonstration](../analysis/scenarios/scenario-demonstration.md).

Comparisons select the lowest excluded broad tuple, the lowest-ID event from each of two
standalone sets, and all prior individual detection comparisons. The encoded-only lineage shows real
ancestry outside the refined predicates. Inventory/directory semantics, Defender-looking
installation, Fax configuration and direct executable service creation retain uncertainty:
appearance or test wording does not establish trust. Two extra corroborating installations
bring the scenario artifact to **18 source records**, separate from the review-unit count.

The [dashboard contract](dashboard.md) uses per-cohort counts, **611 verified activity
rows**, three refined pairs and the bounded primary triple. No measured accuracy or
malicious/benign panel is supported. The [live dashboard](dashboard.md) presents these
validated units. Full incident chronology and automated response are outside scope.
