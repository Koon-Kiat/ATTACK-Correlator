# ATT&CK evidence dashboard

**ATT&CK Detection & Correlation — Windows-APT 2025** is a live, validated Kibana 9.5.3
dashboard in the `attack-correlator` space.
[Open locally](http://localhost:5601/s/attack-correlator/app/dashboards#/view/attack-correlator-windows-apt-2025).

The original [scenario evaluation contract](../analysis/evaluation/dashboard-contract.json) remains
unchanged; its `dashboard_built: false` describes that prerequisite stage.
[dashboard implementation validation](../analysis/dashboard/dashboard-validation.json) records the live implementation.

## Scope and units

All panels retain **2024-11-05T00:00:00.000Z through 2024-12-15T23:59:59.999Z, UTC**.
This covers the exact refined activity interval and every validated broad pair. The
scope panel explains that overview metrics/charts and scenario snapshots stay fixed.
The Detection Event Evidence table accepts membership, search and field filters within
the fixed period. Metrics use aggregation-level cohort filters; chart queries include
explicit time bounds. Markdown scenario panels are generated snapshots.

Counts represent candidates and evidence units, not confirmed attacks. The 611 activity
rows count events within rules; they are not an attack total. Service-create and
service-config remain separate cohorts. An ordered pair is `[shell_id, child_id]`;
an ordered triple is `[installation_id, shell_id, child_id]`.

## Layout and exact sources

| Panels | Source and unit | Validated value |
|---|---|---|
| Scope header | Analyst ATT&CK mappings and historical contract | T1059.001, T1059.003, T1543.003 |
| Four individual metric cards | `record.kind=detection_event`, exact `detection.id`; distinct events within each cohort | 290 / 172 / 41 / 108 |
| Refined correlation metric | `record.kind=correlation_pair`, `correlation.refined=true`; ordered pairs | 3 |
| Refined hosts metric | Distinct `host.name` in refined pair documents | 3 |
| Daily stacked activity | Exact membership documents, ES\|QL UTC daily counts in four series | 611 rows; 290 / 172 / 41 / 108 |
| Host stacked activity | Same membership documents, grouped by host | DS4FBF4, FMI6MML, QGB4EQH |
| Candidate Sequence Volume | All complete broad pairs and refined flags; generated validated snapshot | 261 → 3 ordered pairs |
| Primary relationship and three cards | Three primary scenario rows plus verified GUID/image evidence | One triple / three events / 41,801,900 ns |
| Supporting table | Two corroborating shells; lowest source ID in each refined sc.exe cohort | Four illustrative rows, not corpus denominators |
| Interpretation | Structure, units, plausible FP/FN explanations and coverage limits | No intent/accuracy labels |

There are **19 panels**: eight live Lens visualizations, nine Markdown panels,
one native Discover document table and one membership options control.
The short legend label “Command Shell” means the Windows Command Shell refined cohort.
Each of the four series reconciles by exact day and host as well as by total.

## Detection-result traceability

**Detection Event Evidence** reads `attack-correlator-dashboard-*` with the mandatory
`record.kind: detection_event` query. Its nine columns show timestamp, analyst ATT&CK ID,
technique, detection/rule name, host, user, process, command line and the original `event.id`.
Expand a row for full values or scroll horizontally; unavailable source fields remain empty.
The table and space sample limit are 1,000, above the complete 611-row membership corpus.

Clear other search/filter pills, then choose **Detection membership (evidence table)**:

| Membership | Exact document rows |
|---|---:|
| `powershell_refined` | 290 |
| `shell_refined` | 172 |
| `service_create_refined` | 41 |
| `service_config_refined` | 108 |

With no selection, all 611 memberships are available. Overview metrics stay fixed.
The validator retrieves every ID for each membership, compares the complete sets with
individual detection and the presentation documents, and resolves each ID to exactly one source event.
This supplies record evidence independently of Lens's aggregated **View data** result.

Use the explicit rule links above the table
for complete historical detection rows in Discover. These ES|QL links contain the rule,
record kind and UTC bounds. Kibana 9.5's built-in **Open in Discover** can drop a control
selection; the explicit links preserve the intended cohort instead. Additional ad hoc
filters do not carry into these full-cohort links.

Click a **Source event ID** link to query `windows-apt-events-*` by exact `event.id`.
It opens the corresponding original event, including source provenance, without executing
any displayed command. Relative links stay in the current Kibana space and contain no
saved-object IDs, so clean-space imports remain usable. The URL formatter follows
[Elastic's field formatter documentation](https://www.elastic.co/docs/explore-analyze/find-and-organize/data-views).

## Primary bounded scenario

**DESKTOP-DS4FBF4**, 6 November 2024 UTC:

| Order / analyst technique | Exact timestamp | Source event ID |
|---|---|---|
| 1 · T1543.003 SCM 7045 installation baseline | 2024-11-06T09:58:51.208562600Z | `be75d1504e5784527dfd60bc35420d21f910b57ffba3ffcc1d84ec30c23070f9` |
| 2 · T1059.003 service-origin cmd.exe refined | 2024-11-06T09:58:51.235401Z | `c5a93a534cf031f5789b321d070b3f6cf33ec3e79e50b72cf15e384b7821e8e4` |
| 3 · T1059.001 PowerShell refined | 2024-11-06T09:58:51.250364500Z | `c87894aacb7c79e770e4eb8b1fd95fcf9612bb5fddba0c3f00edea3a9a9d6634` |

Gaps are **26,838,400 ns** and **14,963,500 ns**. The shell actor and PowerShell parent
GUIDs match: `{8e11608b-3ddb-672b-1705-000000000500}`. Preserved SCM imagePath independently
matches the normalized full shell command; this is lexical association, not service API
identity or proof of causality. The 7045 record is outside the refined sc.exe cohorts.
Triple ID: `f09a7676f6f7a5fea1aa767b84a4dbb50411cbdf1d66da690e98aa6a738ffa9c`.

This is a three-event corroborated candidate. Malicious intent, the requested marker
file and final execution outcome are not independently proven. It is not a complete
incident timeline. Missing fields display as **Unavailable**; SCM's `LocalSystem`
service account is separate from process `user.name`. Commands and source IDs render
as inert code text, with no execution or automatic URL opening.

## Presentation and reproduction

`scripts/build_dashboard_data.py` checks individual detection through scenario evaluation hashes/counts and reads 1,096 required
live source IDs. It validates refined memberships, all broad pair structures and all
three triples, then writes **881 deterministic documents** to
`attack-correlator-dashboard-v1`. Complete readback verifies every document. Unexpected
ownership, extra IDs, partial bulk failures or evidence drift stop the run. Source
counts and mapping are checked before and after; no source data is written.

The data view is `attack-correlator-dashboard-*` with `@timestamp` (`date_nanos`).
`timestamp_exact` also retains the original string. `analyst.*`, `detection.*`, `record.*`,
`correlation.*` and `scenario.*` are derived analytics. Source fields, source IDs,
service evidence and provenance retain their separate roles.

```powershell
.\.venv\Scripts\python.exe scripts/build_scenario_evidence.py --reuse-validated-prerequisites
.\.venv\Scripts\python.exe scripts/build_dashboard_data.py
.\.venv\Scripts\python.exe scripts/build_dashboard.py
.\.venv\Scripts\python.exe scripts/validate_dashboard.py
```

The builder uses the installed version's [public Dashboards API](https://dashboardsapispec.kibana.dev/dashboards).
It reads back accepted panels and exports them through Kibana's saved-object API.
After rebuilding an already open dashboard, use **More → Reset changes → Reset dashboard**
and reload if Kibana restores old temporary view settings. This returns to the last
saved dashboard and clears temporary filters/queries; it does not change source data.
[Import instructions](../kibana/README.md) cover the three-object export, UTC settings
and destination-ID remapping. Hand-authored NDJSON is not used as a substitute for a live export.

## Visual evidence and limitations

Real browser evidence is in `analysis/dashboard/visual-inspection.json` and
`analysis/dashboard/screenshots/`. Inspection covers the overview, primary sequence,
supporting evidence and imported dashboard: layout, readable strings, units, UTC,
visible disclaimers and panel errors. A nonmatching global host query and different
global time window verify fixed-scope behavior.

**261 → 3 is candidate sequence volume reduction, not measured false-positive reduction.**
Both sets already require ancestry, ordering and bounded time; refinement adds service
origin and refined child behavior. Authorized administration/tests can still match.
Missing logs/GUIDs, alternate parents or interpreters, in-process PowerShell and delays
can prevent correlation. No independent intent truth supports precision, recall, F1,
FPR, severity or confidence charts. See [limitations](limitations.md).
