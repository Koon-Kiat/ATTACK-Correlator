"""Render evidence-derived Markdown reports; no handwritten statistics or detections."""

from __future__ import annotations

import html
import json
from pathlib import Path

from src.preprocessing.profile_values import technique_kind
from src.preprocessing.windows_fields import ECS_CANDIDATES, GROUPS


def cell(value) -> str:
    if value is None:
        return "Unavailable"
    if isinstance(value, (dict, list)):
        value = json.dumps(value, sort_keys=True, ensure_ascii=False)
    return (
        html.escape(str(value), quote=False)
        .replace("|", "&#124;")
        .replace("`", "&#96;")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
    )


def table(headers, rows) -> str:
    return (
        "\n".join(
            [
                "| " + " | ".join(map(cell, headers)) + " |",
                "| " + " | ".join("---" for _ in headers) + " |",
                *["| " + " | ".join(map(cell, row)) + " |" for row in rows],
            ]
        )
        + "\n"
    )


def counts_text(values: dict) -> str:
    return "; ".join(f"{key}: {value}" for key, value in sorted(values.items())) or "None observed"


def intro(title: str) -> list[str]:
    return [
        f"# {title}\n",
        "Generated from raw dataset bytes by `python -m src.preprocessing.evidence_inventory`. "
        "The input and output SHA-256 values are retained in `inventory-manifest.json`. "
        "This is Phase 2 inspection; no normalization, ingestion, final "
        "technique selection or detection rule is implemented.\n",
    ]


def write(path, parts):
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")


def render_inventory(output: Path, schema: dict, data: dict):
    corpus = data["corpus"]
    parts = intro("Windows-APT 2025 v4 dataset inventory")
    parts += [
        "## Dataset overview\n",
        f"The raw tree contains **{len(schema['file_inventory'])} files**, including "
        f"**{sum(item['format'] == 'csv' for item in schema['file_inventory'])} CSVs**. "
        f"The selected per-period corpus has **{corpus['exported_rows']:,} exported rows** and "
        f"**{corpus['coverage_events']:,} distinct source documents/payloads**. "
        "The combined export and scenario-mapping table are separate "
        "representations, not additional events.\n",
        f"Corpus policy: {corpus['corpus_policy']}. Count unit: {corpus['count_unit']}.\n",
        "## File inventory\n",
    ]
    profiles = {item["path"]: item for item in schema["files"]}
    parts.append(
        table(
            [
                "File relative to dataset/raw",
                "Format",
                "Bytes",
                "Parsed rows/documents",
                "Duplicate rows",
                "Complete scan",
            ],
            [
                (
                    file["path"],
                    file["format"],
                    file["bytes"],
                    profiles.get(file["path"], {}).get("valid_records", "Not tabular telemetry"),
                    profiles.get(file["path"], {}).get("duplicate_records", "N/A"),
                    profiles.get(file["path"], {}).get("scan_complete", "N/A"),
                )
                for file in schema["file_inventory"]
            ],
        )
    )
    parts += [
        "A notebook is one JSON document, not one security event. Publisher "
        "scripts were inspected as source text and never executed. "
        "Checksums, readable status, exact columns, typed examples, nulls and"
        " distinct-value limits are in `dataset_schema.json`.\n",
        "## Data quality and overlap\n",
        table(
            ["Check", "Observed result"],
            [
                (
                    "Empty files",
                    [item["path"] for item in schema["file_inventory"] if item["empty"]],
                ),
                (
                    "Unreadable files",
                    [item["path"] for item in schema["file_inventory"] if not item["readable"]],
                ),
                (
                    "Malformed structured records",
                    sum(item["malformed_records"] for item in schema["files"]),
                ),
                (
                    "Incomplete structured scans",
                    [item["path"] for item in schema["files"] if not item["scan_complete"]],
                ),
                (
                    "Exact duplicate exported rows in period corpus",
                    corpus["exact_duplicate_export_rows"],
                ),
                ("Repeated document identities", corpus["duplicate_identity_rows"]),
                ("Identities with conflicting payloads", corpus["conflicting_document_identities"]),
                ("Combined rows", corpus["combined_export_rows"]),
                (
                    "Positional joins with equal _index/_id",
                    corpus["combined_positional_identity_matches"],
                ),
                (
                    "Positional identity mismatches",
                    corpus["combined_positional_identity_mismatches"],
                ),
                (
                    "Exact aligned-payload overlap with period files",
                    corpus["combined_exact_payload_overlap"],
                ),
                ("Combined-only payload rows", corpus["combined_only_payload_rows"]),
                ("Period-only payload rows", corpus["period_only_payload_rows"]),
                ("Malformed event label arrays", corpus["label_parse_problems"]),
            ],
        ),
        "Overlap comparison aligns column names and treats an absent column "
        "like an empty cell; all nonempty values, "
        "including whitespace and numeric spelling, remain exact. Duplicate "
        "handling affects analytical counts only; no source row is removed. "
        "Zero parse failures does not establish semantically complete "
        "telemetry. JSON null/whitespace empties are counted separately from "
        "absent columns. "
        "Literal NA/null strings remain source values. Distinct-value counts "
        "capped at 10,000 are labelled lower bounds.\n",
        "### Representation differences\n",
        table(
            [
                "Source field",
                "Changed rows",
                "Period file and row",
                "Period value",
                "Combined value",
            ],
            [
                (
                    field,
                    count,
                    f"{corpus['combined_field_difference_examples'][field]['source_csv']}:{corpus['combined_field_difference_examples'][field]['row_index']}",
                    corpus["combined_field_difference_examples"][field]["period_value"],
                    corpus["combined_field_difference_examples"][field]["combined_value"],
                )
                for field, count in corpus["combined_field_difference_counts"].items()
            ],
        ),
        "Field differences are compared only after confirming equal document "
        "identities. They include changes in representation, "
        "not additional events. Review numeric precision, lost leading zeros,"
        " case changes, partial-clock strings and spreadsheet error values. "
        "Prefer period files for the verified scenario join, but retain "
        "combined.csv for comparison because neither representation is "
        "uniformly lossless.\n",
        "## Log sources\n",
    ]
    for field, values in corpus["log_sources"].items():
        parts += [
            f"### {field}\n",
            table(
                ["Observed value", "Export rows"],
                sorted(values.items(), key=lambda item: (-item[1], item[0])),
            ),
        ]
    parts += [
        "## Hosts and dataset-provided context\n",
        table(
            ["Agent name", "Documents", "With Wazuh ATT&CK labels", "With Windows UTC time"],
            [
                (
                    name,
                    values["events"],
                    values["with_event_technique_labels"],
                    values["windows_event_timestamps"],
                )
                for name, values in corpus["agents"].items()
            ],
        ),
        "The supplement README identifies Maryam as infrastructure. Its rows "
        "are a **candidate** background pool, "
        "not an independently labelled benign set; the table explicitly shows"
        " any existing technique tags. "
        "Agent labels and originating Windows computer names are different "
        "fields. No OS-name/version column is supplied by the inspected event"
        " schema; "
        "syscheck architecture describes checked objects and must not be "
        "assumed to be the host OS.\n",
        "## Available telemetry\n",
        "All following source columns actually exist. Counts use exported "
        "period rows; examples are exact prefixes with truncation noted. "
        "Full schemas and per-file null, type, distinct and embedded-JSON "
        "statistics are in `dataset_schema.json`.\n",
    ]
    for group, fields in data["telemetry_groups"].items():
        parts += [
            f"### {group.replace('_', ' ')}\n",
            table(
                ["Dataset field", "Nonempty rows", "Empty or absent rows", "Example"],
                [
                    (
                        field,
                        corpus["fields"][field]["nonempty_export_rows"],
                        corpus["fields"][field]["empty_or_absent_export_rows"],
                        (
                            (corpus["fields"][field]["example"] or {}).get("value", "Unavailable")
                            + (
                                " [truncated]"
                                if (corpus["fields"][field]["example"] or {}).get("truncated")
                                else ""
                            )
                        ),
                    )
                    for field in fields
                ],
            ),
        ]
    parts += [
        "## Timestamp observations\n",
        table(["Check", "Measured result"], list(corpus["timestamp_quality"].items())),
        "The display timestamp lacks a timezone; its difference from UTC "
        "event time is a wall-clock diagnostic, not a verified timezone "
        "offset. "
        "Numeric utcTime values are tested against the Excel 1899-12-30 "
        "hypothesis only where an embedded original UTC string exists. "
        "That comparison is not a normalization policy; rounding/precision "
        "and source-clock meaning must be settled in Phase 3. "
        "Correlation exploration uses only explicit-offset Windows systemTime"
        " and excludes rows without it. "
        "Microseconds are used for interval calculations; original strings "
        "preserve greater precision.\n",
        "### Original-message availability\n",
        table(["Full-log representation", "Rows"], corpus["full_log_value_shapes"].items()),
        "Plain-text original messages are legitimate formats, not "
        "automatically malformed JSON. Preserve the CSV row when full_log is "
        "absent.\n",
        "## Scenarios and ground truth\n",
        f"Manifest rows: **{len(corpus['manifest'])}**; "
        f"validation rows: **{len(corpus['validation'])}**; "
        f"mapping rows: **{corpus['mapping']['rows']:,}**.\n",
        table(
            ["Metadata file", "Observed columns"],
            [
                ("scenario_manifest.csv", list(corpus["manifest"][0])),
                ("validation_summary.csv", list(corpus["validation"][0])),
                ("log_to_scenario_mapping.csv", corpus["mapping"]["columns"]),
            ],
        ),
        "Manifest/validation use the source spelling `Scenrario_ID`; mapping uses `Scenario_ID`. "
        "The verified event join is `(Source_CSV, Row_Index)` with "
        "**zero-based parsed row indices in each period CSV**. "
        "A physical file line is different when CSV fields contain newlines.\n",
        table(
            ["Join check", "Result"],
            [
                ("Matched event rows", corpus["mapping"]["join_checks"].get("matched_event", 0)),
                (
                    "Unmatched event rows",
                    corpus["mapping"]["join_checks"].get("unmatched_event", 0),
                ),
                ("Orphan mapping keys", corpus["mapping"]["orphan_mapping_keys"]),
                ("Duplicate mapping keys", corpus["mapping"]["duplicate_join_keys"]),
                (
                    "Timestamp / Agent_Name / MITRE_Technique mismatches",
                    {
                        key: corpus["mapping"]["join_checks"].get(key + "_mismatch", 0)
                        for key in ["Timestamp", "Agent_Name", "MITRE_Technique"]
                    },
                ),
                (
                    "Unknown assigned scenarios",
                    corpus["mapping"]["join_checks"].get("unknown_scenario", 0),
                ),
                ("Mapping source files", corpus["mapping"]["source_files"]),
            ],
        ),
        "The README's example join using Source_CSV=combined.csv does not "
        "match this supplied mapping, whose keys name period CSVs. "
        "The supplement README also refers to Subset_masked_by, which is "
        "absent from the inspected mapping schema. "
        "MITRE_Group_ID contains dataset-provided group names; preserve it "
        "without pretending those values are canonical G-number IDs.\n",
        table(["Attribution_Strength", "Rows"], corpus["mapping"]["strengths"].items()),
        table(["Derived_Label", "Rows"], corpus["mapping"]["derived_labels"].items()),
        "These are post-hoc scenario attributions derived from Wazuh "
        "technique tags and episode context. "
        "UNIQUE-MATCH/NARROWED are stronger assignments within that method, "
        "not independently verified attacks. "
        "Untagged does not mean benign. The supplied metadata has no observed"
        " per-event binary malicious/benign ground-truth column, "
        "attack-step ID or authoritative scenario start/end boundaries. "
        "Observed event min/max times do not replace execution boundaries.\n",
        "### Expected-versus-observed metadata checks\n",
        table(
            [
                "Scenario",
                "Manifest IDs",
                "Declared expected",
                "Avg succeeded",
                "Reported %",
                "Avg/declared %",
            ],
            [
                (
                    row["scenario"],
                    row["manifest_technique_count"],
                    row["declared_expected_count"],
                    row["average_succeeded"],
                    row["reported_success_percent"],
                    row["ratio_using_declared_count_percent"],
                )
                for row in corpus["validation_comparisons"]
            ],
        ),
        "The recalculated ratio is a consistency check, not detection "
        "accuracy. Differences may reflect rounded averages or "
        "different denominators in the publisher's validation notes; these "
        "summaries cannot supply event-level TP/FP/FN/TN.\n",
        "## Phase 3 questions\n",
        "Settle event versus collection time, serial-date precision, escaped "
        "strings, provider-aware event semantics, explicit rejection "
        "accounting, "
        "source identity and row-index preservation. Use the verified "
        "period-file join and keep original and derived labels apart from "
        "detector inputs. "
        "Review raw examples of each candidate before selecting the final "
        "three in the later selection phase.\n",
    ]
    write(output / "dataset_inventory.md", parts)


def render_coverage(output: Path, schema: dict, data: dict):
    observed = data["coverage"]
    mentions = data["mentions"]["technique_identifiers"]
    parents = [ident for ident in observed if technique_kind(ident) == "parent-technique"]
    subs = [ident for ident in observed if technique_kind(ident) == "sub-technique"]
    parts = intro("ATT&CK evidence coverage and correlation candidates")
    parts += [
        "## Counting scope\n",
        f"The nonduplicated event corpus carries **{len(parents)} parent-technique** "
        f"and **{len(subs)} sub-technique** "
        f"Wazuh labels. Across all structured values, documentation and publisher code, there are "
        f"**{sum(value['kind'] == 'parent-technique' for value in mentions.values())} "
        "parent-shaped** and "
        f"**{sum(value['kind'] == 'sub-technique' for value in mentions.values())} "
        "sub-technique-shaped** identifiers. "
        "The latter includes metadata, assessment references and text "
        "examples, not confirmed occurrences.\n",
        *["- " + note for note in data["counting_notes"]],
        "",
        "Names below come only from unambiguous one-ID/one-name source rows. "
        "Unresolved names are left blank; "
        "co-labelled source names are retained separately in the "
        "machine-readable evidence. Tactic lists describe co-labels, not "
        "inferred assignments.\n",
        "## Event-labelled parent techniques\n",
        table(
            ["ID", "Unambiguous dataset name", "Source documents", "Files", "Derived scenarios"],
            [
                (
                    ident,
                    observed[ident]["unambiguous_dataset_names"],
                    observed[ident]["event_count"],
                    len(observed[ident]["files"]),
                    counts_text(observed[ident]["derived_scenarios"]),
                )
                for ident in parents
            ],
        ),
        "## Event-labelled sub-techniques\n",
        table(
            [
                "ID",
                "Unambiguous dataset name",
                "Source documents",
                "Behavioural detail",
                "UTC Windows time",
                "Expected manifest scenarios",
                "Stronger derived assignments",
            ],
            [
                (
                    ident,
                    observed[ident]["unambiguous_dataset_names"],
                    observed[ident]["event_count"],
                    observed[ident]["behavioral_detail_events"],
                    observed[ident]["windows_event_time_utc"]["count"],
                    observed[ident]["manifest_expected_scenarios"],
                    counts_text(observed[ident]["stronger_derived_scenarios"]),
                )
                for ident in subs
            ],
        ),
        "Event-level labels establish what the dataset annotates. They do not"
        " by themselves establish successful malicious execution. "
        "The evidence examples distinguish actual observed processes, file "
        "changes, module loads and network activity. "
        "For example, a task scheduler DLL load is weaker evidence than an "
        "observed task registration; a file-deletion command line "
        "is evidence of an attempted action rather than proof that the file "
        "was deleted. No final three techniques are chosen.\n",
        "## Candidate suitability\n",
        "These simple ratings measure analytical usability, not accuracy. "
        "Volume: Strong >=1,000, Moderate >=100; "
        "field coverage: Strong >=80%, Moderate >=25% have "
        "command/file/object/module/network detail. "
        "Evidence quality is at most Moderate because original rule labels "
        "remain unvalidated. Ground truth and "
        "benign comparison are Weak without independent labels. SIEM "
        "usability is Strong at >=100 rows and >=80% detail. "
        "Correlation is Strong with >=10 exclusive-label structural pair observations within "
        "300 seconds, Moderate with any candidate relation. "
        "Dashboard usefulness is Strong at >=100 rows with detail. Each "
        "reason gives the underlying counts.\n",
        table(
            [
                "ID",
                "Volume",
                "Evidence",
                "Fields",
                "Truth",
                "Benign",
                "SIEM",
                "Correlation",
                "Dashboard",
                "Reason",
            ],
            [
                (
                    ident,
                    *[
                        rating[key]
                        for key in [
                            "event_volume",
                            "evidence_quality",
                            "observable_field_coverage",
                            "ground_truth",
                            "benign_comparison",
                            "siem_detection",
                            "correlation",
                            "dashboard",
                        ]
                    ],
                    rating["explanation"],
                )
                for ident, rating in data["candidate_ratings"].items()
            ],
        ),
        "## Correlation shortlist\n",
        "Candidates are sorted by exclusive-label process-GUID/parent-child pair observations"
        " within 300 seconds; this is a structural shortlist, "
        "not an automatic technique selection. Only distinct source documents"
        " with an explicit Windows UTC timestamp and computer "
        "are eligible. For non-parent relationships the algorithm chooses the"
        " nearest preceding event per other label in each context. "
        "It tests 60/300/900-second windows. Pair counts are neither all "
        "possible joins nor detection alerts; relation categories overlap. "
        "Zero time differences are ties, not proven ordering. Host/user/time "
        "or scenario agreement alone does not imply causality. "
        "The exclusive-label column requires A without B on one document and "
        "B without A on the other. It helps expose repeated co-labelling; "
        "it does not independently validate either behaviour.\n",
    ]
    parts += [
        "### Repeated co-labels requiring caution\n",
        table(
            ["Labels", "Structural observations <=300s", "Exclusive-label observations <=300s"],
            [
                (
                    candidate["techniques"],
                    candidate["structural_pairs_within_300_seconds"],
                    candidate["exclusive_structural_pairs_within_300_seconds"],
                )
                for candidate in data["correlation_candidates"]
                if candidate["structural_pairs_within_300_seconds"]
                and not candidate["exclusive_structural_pairs_within_300_seconds"]
            ],
        ),
        "Even distinct documents can repeat the same pair of labels. These combinations "
        "do not establish two separately observed behaviours.\n",
    ]
    shortlist = sorted(
        data["correlation_candidates"],
        key=lambda item: (
            -item["exclusive_structural_pairs_within_300_seconds"],
            item["techniques"],
        ),
    )[:8]
    review_notes = {
        ("T1059.003", "T1070.004"): (
            "Shell ancestry is observable, but the displayed child updater.exe -Command exit "
            "does not itself show deletion despite its source label. Review full commands "
            "and independent file events before treating this pair as deletion evidence."
        ),
        ("T1053.005", "T1059.003"): (
            "The same-GUID example connects schtasks /create command telemetry to a "
            "taskschd.dll load. This supports further review of task-creation attempts. "
            "The parent-child example instead involves sedlauncher and powercfg: a useful "
            "routine-administration comparison candidate, not verified benign truth. "
            "Module loading alone does not prove task registration."
        ),
        ("T1059.001", "T1059.003"): (
            "The child command and parent GUID support shell-to-PowerShell execution "
            "context, including a script in a temporary location in the displayed example. "
            "Execution and ancestry are observable; malicious intent needs additional evidence."
        ),
        ("T1059.001", "T1070.004"): (
            "The parent-child example contains nested PowerShell remove-item commands. "
            "It supports attempted deletion and interpreter ancestry, not a proven file outcome. "
            "The same-GUID example contains updater.exe -Command exit and an automation "
            "library load, showing why the existing deletion label cannot be trusted alone."
        ),
        ("T1053.005", "T1574.001"): (
            "The example links a Windows SoftwareDistribution DLL file creation to a "
            "task scheduler module load by svchost. The GUID relationship is real, but "
            "routine update activity is a plausible explanation; hijacking is not proven."
        ),
        ("T1053.005", "T1574.002"): (
            "The example links a Windows SoftwareDistribution DLL file creation to a "
            "task scheduler module load by svchost. A created DLL is not proof it was "
            "loaded by the process or used for side-loading."
        ),
        ("T1059.003", "T1059.005"): (
            "The example links a WScript command to its whoami child. Interpreter "
            "ancestry is observable; script contents and intent require separate review."
        ),
        ("T1059.003", "T1548.002"): (
            "The example links ComputerDefaults.exe to a cmd.exe child and preserves "
            "the earlier PowerShell registry-related command in parent context. Review "
            "associated registry and token/integrity evidence before claiming UAC bypass."
        ),
    }
    for candidate in shortlist:
        parts += [
            "### " + " + ".join(candidate["techniques"]) + "\n",
            "Shared derived scenarios: "
            + cell(counts_text(candidate["shared_derived_scenarios"]))
            + ". "
            "Computers: " + cell(counts_text(candidate["hosts"])) + ".\n",
            f"Eligible individual documents carrying both labels: "
            f"{candidate['co_labelled_eligible_documents']}. These single documents "
            "are never counted as a two-event correlation.\n",
            table(
                [
                    "Relationship",
                    "Pairs <=60s",
                    "Pairs <=300s",
                    "Exclusive-label pairs <=300s",
                    "Pairs <=900s",
                    "Median gap (s)",
                    "Same derived scenario",
                    "Both stronger assignment",
                ],
                [
                    (
                        name,
                        info["pairs_by_maximum_window_seconds"]["60"],
                        info["pairs_by_maximum_window_seconds"]["300"],
                        info["exclusive_label_pairs_by_maximum_window_seconds"]["300"],
                        info["pairs_by_maximum_window_seconds"]["900"],
                        info["median_gap_seconds"],
                        info["same_derived_scenario_pairs"],
                        info["same_stronger_derived_scenario_pairs"],
                    )
                    for name, info in candidate["relations"].items()
                ],
            ),
            "Potential: an exact actor GUID or parent/child GUID ties separate "
            "observations to process context; "
            "the later phase can test whether the supporting event improves a "
            "baseline. DLL-load and routine administrative "
            "contexts may still be benign. The scenario assignments are derived "
            "from overlapping technique sets.\n",
        ]
        note = review_notes.get(tuple(candidate["techniques"]))
        if note:
            parts.append("Interpretation of the displayed source examples: " + note + "\n")
        structural = [
            value
            for key, value in candidate["relations"].items()
            if key in {"parent_child_process_guid", "same_actor_process_guid"}
        ]
        for relation in structural[:2]:
            for example in (relation["exclusive_examples"] or relation["examples"])[:1]:
                parts += [
                    f"Evidence key: {cell(example['key'])}; "
                    f"gap {example['gap_seconds']} seconds.\n",
                    table(
                        [
                            "Side",
                            "File: zero-based row",
                            "Event labels",
                            "Scenario/strength",
                            "Observed fields",
                        ],
                        [
                            (
                                side,
                                f"{example[side]['source_csv']}:{example[side]['row_index']}",
                                example[side]["event_labels"],
                                f"{example[side]['scenario']} / "
                                f"{example[side]['attribution_strength']}",
                                example[side]["fields"],
                            )
                            for side in ["left", "right"]
                        ],
                    ),
                ]
    parts += ["## Evidence by observed sub-technique\n"]
    for ident in sorted(subs, key=lambda key: (-observed[key]["event_count"], key)):
        info = observed[ident]
        parts += [
            f"### {ident}\n",
            f"Source documents: **{info['event_count']}**. "
            f"Names: {cell(info['unambiguous_dataset_names'])}; "
            f"co-labelled names: {cell(info['co_labelled_names'])}.\n",
            table(
                ["Context", "Observed evidence"],
                [
                    ("Files", info["files"]),
                    ("Agents", info["agents"]),
                    ("Computers", info["computers"]),
                    ("Users by source role", info["users_by_source_field"]),
                    ("Provider / event code", info["provider_event_codes"]),
                    ("Source rule descriptions (annotations)", info["rule_descriptions"]),
                    ("Manifest expected scenarios", info["manifest_expected_scenarios"]),
                    ("Derived scenario attribution", info["derived_scenarios"]),
                    ("Stronger derived attribution", info["stronger_derived_scenarios"]),
                    ("Tactic co-labels", info["tactic_co_labels"]),
                    ("UTC event time", info["windows_event_time_utc"]),
                    ("Display time; timezone unassigned", info["display_time_timezone_unassigned"]),
                    ("Derived label values", info["derived_labels"]),
                    ("Independent truth", info["independent_benign_malicious_truth"]),
                ],
            ),
            table(
                ["Actual supporting field", "Nonempty labelled documents"],
                [
                    (field, count)
                    for field, count in info["field_nonempty_events"].items()
                    if field in set(GROUPS["process"] + GROUPS["file_registry"] + GROUPS["network"])
                ],
            ),
            table(
                ["Source file", "Row index", "Rule and telemetry excerpt"],
                [
                    (example["source_csv"], example["row_index"], example["fields"])
                    for example in info["examples"]
                ],
            ),
        ]
    parts += [
        "## All identifier mentions, including references\n",
        "This table deliberately includes reference-only identifiers. "
        "Pattern-shaped IDs may be stale names or payload/comment text; "
        "no external ATT&CK name map was introduced. SCA catalogue references"
        " are not evidence that the referenced technique executed. "
        "All file/field locations are in `attack_evidence.json`; "
        "`attack_coverage.csv` provides a flat inventory.\n",
        table(
            [
                "Identifier",
                "Kind",
                "Event-label count",
                "Event-row text mentions",
                "SCA reference rows",
                "Files mentioning ID",
            ],
            [
                (
                    ident,
                    value["kind"],
                    observed.get(ident, {}).get("event_count", 0),
                    data["corpus"]["all_technique_text_mentions_in_event_rows"].get(ident, 0),
                    data["corpus"]["assessment_reference_rows"].get(ident, 0),
                    len({loc["file"] for loc in value["locations"]}),
                )
                for ident, value in mentions.items()
            ],
        ),
        "Other ATT&CK identifier families are inventoried separately (not counted as techniques): "
        + cell(data["mentions"]["other_identifier_families"])
        + ".\n",
        "Event semantics reference: [Microsoft Sysmon documentation]"
        "(https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon). "
        "Process creation, module loading and file creation are different observations; "
        "none alone establishes the ATT&CK behaviour named by a Wazuh rule.\n",
    ]
    write(output / "attack_coverage.md", parts)


def render_ecs(output: Path, data: dict):
    fields = data["corpus"]["fields"]
    parts = intro("Candidate ECS mappings — proposals only")
    parts += [
        "These are source-semantic proposals, not implemented mappings. The "
        "exact source columns and examples below "
        "come from the current period corpus. Confidence concerns semantic "
        "fit, not proof that all values are valid.\n",
        table(
            ["Dataset Field", "Example", "Proposed ECS Field", "Confidence", "Reason"],
            [
                (
                    field,
                    fields[field]["example"]["value"]
                    + (" [truncated]" if fields[field]["example"]["truncated"] else ""),
                    target,
                    confidence,
                    reason,
                )
                for field, target, confidence, reason in ECS_CANDIDATES
                if field in fields and fields[field]["example"]
            ],
        ),
        "## Explicitly unresolved mappings\n",
        "- No OS name/version field is inferred from the dataset title or manager name.\n"
        "- No universal user mapping merges actor, subject and target accounts.\n"
        "- Numeric utcTime/creationUtcTime values need source-format "
        "validation; no epoch or spreadsheet conversion is applied.\n"
        "- imagePath may contain service command arguments and cannot blindly"
        " become process.executable.\n"
        "- Windows system.processID is provider context, not automatically "
        "the activity's process.pid.\n"
        "- ipAddress/ipPort on authentication events need event-specific direction semantics.\n"
        "- Original IDs and source row metadata need an explicit "
        "identity/provenance contract; mapping-only Source_CSV/Row_Index are "
        "join metadata.\n"
        "- event.category/event.type need a reviewed provider+event-code "
        "lookup. They are not direct copied columns.\n"
        "- Keep Wazuh technique annotations and derived scenario truth in a "
        "separate provenance namespace until enrichment semantics are agreed."
        "\n",
        "## ECS semantics checked\n",
        "References: [process fields](https://www.elastic.co/docs/reference/ecs/ecs-process), "
        "[event fields](https://www.elastic.co/docs/reference/ecs/ecs-event), "
        "[host fields](https://www.elastic.co/docs/reference/ecs/ecs-host), "
        "[source fields](https://www.elastic.co/docs/reference/ecs/ecs-source), "
        "[file fields](https://www.elastic.co/docs/reference/ecs/ecs-file), "
        "[registry fields](https://www.elastic.co/docs/reference/ecs/ecs-registry), "
        "[user fields](https://www.elastic.co/docs/reference/ecs/ecs-user). "
        "The dataset remains the source for field presence and examples. "
        "Recheck the selected ECS version in Phase 3.\n",
    ]
    write(output / "ecs_mapping_candidates.md", parts)


def render_reports(output: Path, schema: dict, data: dict):
    render_inventory(output, schema, data)
    render_coverage(output, schema, data)
    render_ecs(output, data)
