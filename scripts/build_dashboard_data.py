"""Deterministic presentation of validated analytics, never a new detection engine."""

import json
import sys
from collections import Counter
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.build_scenario_evidence import (  # noqa: E402
    CONTRACT,
    EVALUATION,
    REFINED,
    SCENARIO,
    live_state,
    source_projection,
    verify_hashes,
    verify_prerequisites,
    verify_triples,
)
from scripts.elastic_local import ROOT, load_json, request, save_json  # noqa: E402
from scripts.kibana_local import http  # noqa: E402
from scripts.run_correlation import event_lookup, lineage_pairs, pair_record, sha_json  # noqa: E402
from scripts.run_individual_detections import (  # noqa: E402
    EVIDENCE_FIELDS,
    fetch_evidence,
    field,
    source_matches,
)
from scripts.verify_technique_selection import require  # noqa: E402
from src.preprocessing.preprocess import digest  # noqa: E402

INDEX = "attack-correlator-dashboard-v1"
DATA_VIEW = "attack-correlator-dashboard-v1"
PATTERN = "attack-correlator-dashboard-*"
SPACE = "attack-correlator"
TIME_RANGE = {"from": "2024-11-05T00:00:00.000Z", "to": "2024-12-15T23:59:59.999Z"}
RULE_COUNTS = {
    "powershell_refined": 290,
    "shell_refined": 172,
    "service_create_refined": 41,
    "service_config_refined": 108,
}
RULE_NAMES = {
    "powershell_refined": "PowerShell refined",
    "shell_refined": "Windows Command Shell refined",
    "service_create_refined": "Service-create refined",
    "service_config_refined": "Service-config refined",
}
TECHNIQUES = {
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1543.003": "Windows Service",
}
UNITS = {
    "detection_event": "event within rule",
    "correlation_pair": "ordered pair",
    "scenario_event": "event within triple",
}
OWNER = {
    "project": "ATTACK-Correlator",
    "purpose": "validated presentation only",
    "schema_version": 1,
}
MANIFEST = "analysis/dashboard/presentation-manifest.json"
FORBIDDEN = {"malicious", "benign", "severity", "risk", "risk_score", "confidence", "ground_truth"}


def prerequisites(root=ROOT):
    p6, p7 = verify_prerequisites(root)
    p8, contract, scenario = [load_json(root / p) for p in (EVALUATION, CONTRACT, SCENARIO)]
    require(
        p8.get("passed") is True and scenario.get("passed") is True, "scenario evaluation must pass"
    )
    for key in ("input_sha256", "output_sha256", "query_sha256"):
        require(bool(p8[key]), f"Missing scenario evaluation {key}")
        verify_hashes(root, p8[key])
    verify_hashes(root, contract["input_sha256"])
    require(contract["timezone"] == "UTC", "UTC contract required")
    for rule, count in RULE_COUNTS.items():
        require(
            contract["individual_metrics"][rule]["distinct_event_count"] == count,
            f"Contract rule count drift: {rule}",
        )
    for name, count in (("broad", 261), ("refined", 3), ("three_event", 3)):
        require(
            contract["correlation_metrics"][name]["tuple_count"] == count,
            f"Contract tuple drift: {name}",
        )
    require(contract["primary_scenario"] == scenario["primary"], "Primary scenario drift")
    return p6, p7, p8, contract, scenario


def source_ids(p7, p8, scenario):
    return sorted(
        {r["event_id"] for r in p8["activity"]["event_rows"]}
        | {i for p in p7["windows"]["60"]["broad"]["tuples"] for i in p["event_ids"]}
        | set(scenario["evidence"])
    )


def document_id(kind, *keys):
    require(kind in UNITS and bool(keys), "Invalid document unit")
    return f"{kind}:{sha_json(list(keys))}"


def no_unsupported_fields(value):
    if isinstance(value, dict):
        require(not (set(value) & FORBIDDEN), "Unsupported classification field")
        for item in value.values():
            no_unsupported_fields(item)
    elif isinstance(value, list):
        for item in value:
            no_unsupported_fields(item)


def event_document(source, attack_id, category):
    projection = source_projection(source)
    process = source.get("process") or {}
    parent = process.get("parent") or {}
    return {
        "@timestamp": source["@timestamp"],
        "timestamp_exact": source["@timestamp"],
        "host": {"name": field(source, "host.name")},
        "event": {k: field(source, f"event.{k}") for k in ("id", "provider", "code")},
        "user": {"name": field(source, "user.name"), "domain": field(source, "user.domain")},
        "process": {
            **{k: process.get(k) for k in ("name", "executable", "command_line", "entity_id")},
            "parent": {k: parent.get(k) for k in ("name", "command_line", "entity_id")},
        },
        "analyst": {
            "attack_id": attack_id,
            "technique": TECHNIQUES[attack_id],
            "mapping_basis": "verified behaviour and validated query membership",
        },
        "source": {"event_ids": [field(source, "event.id")]},
        "service_evidence": projection["service_source_evidence"],
        "evidence": {"category": category, "provenance": projection["provenance"]},
    }


def build_documents(p7, p8, scenario, lookup):
    documents = {}

    def add(kind, keys, value):
        identifier = document_id(kind, *keys)
        require(identifier not in documents, "Duplicate presentation identity")
        documents[identifier] = {"record": {"kind": kind, "unit": UNITS[kind]}, **value}

    for row in p8["activity"]["event_rows"]:
        source = lookup[row["event_id"]]
        require(
            source["@timestamp"] == row["timestamp"] and field(source, "host.name") == row["host"],
            "Activity timestamp/host drift",
        )
        rule = row["detection_name"]
        require(REFINED[rule] == row["attack_id"], "Analyst technique mapping drift")
        value = event_document(source, row["attack_id"], "refined individual candidate")
        value["detection"] = {"id": rule, "name": RULE_NAMES[rule]}
        add("detection_event", (rule, row["event_id"]), value)
    refined = {p["correlation_id"] for p in p7["windows"]["60"]["refined"]["tuples"]}
    for pair in p7["windows"]["60"]["broad"]["tuples"]:
        add(
            "correlation_pair",
            (pair["correlation_id"],),
            {
                "@timestamp": pair["timestamps"][0],
                "timestamp_exact": pair["timestamps"][0],
                "host": {"name": pair["host"]},
                "source": {"event_ids": pair["event_ids"]},
                "correlation": {
                    "id": pair["correlation_id"],
                    "refined": pair["correlation_id"] in refined,
                    "shell_event_id": pair["event_ids"][0],
                    "powershell_event_id": pair["event_ids"][1],
                    "start": pair["timestamps"][0],
                    "end": pair["timestamps"][1],
                    "gap_nanoseconds": pair["gap_nanoseconds"],
                    "window_seconds": 60,
                    "relationship": "same host; exact GUID ancestry; ordered; within 60 seconds",
                },
            },
        )
    for triple in [scenario["primary"], *scenario["corroborating"]]:
        for position, (source_id, attack_id, role) in enumerate(
            zip(
                triple["event_ids"],
                ("T1543.003", "T1059.003", "T1059.001"),
                (
                    "SCM 7045 installation baseline",
                    "Service-origin cmd.exe refined",
                    "PowerShell refined",
                ),
                strict=True,
            ),
            1,
        ):
            value = event_document(
                lookup[source_id], attack_id, "three-event corroborated candidate"
            )
            value["scenario"] = {
                "id": triple["correlation_id"],
                "primary": triple == scenario["primary"],
                "position": position,
                "role": role,
                "span_nanoseconds": triple["span_nanoseconds"],
            }
            add("scenario_event", (triple["correlation_id"], source_id), value)
    validate_documents(documents)
    return dict(sorted(documents.items()))


def validate_documents(documents):
    no_unsupported_fields(documents)
    values = list(documents.values())
    counts = Counter(v["record"]["kind"] for v in values)
    require(
        counts == {"detection_event": 611, "correlation_pair": 261, "scenario_event": 9},
        "Presentation record count mismatch",
    )
    for v in values:
        require(v["record"]["unit"] == UNITS[v["record"]["kind"]], "Analytical unit drift")
        require(
            bool(v["source"]["event_ids"]) and all(v["source"]["event_ids"]), "Missing source ID"
        )
    rules = Counter(
        v["detection"]["id"] for v in values if v["record"]["kind"] == "detection_event"
    )
    require(rules == RULE_COUNTS, "Per-rule presentation count mismatch")
    pairs = [v for v in values if v["record"]["kind"] == "correlation_pair"]
    require(len({tuple(v["source"]["event_ids"]) for v in pairs}) == 261, "Duplicate broad pair")
    refined = [v for v in pairs if v["correlation"]["refined"]]
    require(
        len(refined) == 3 and len({v["host"]["name"] for v in refined}) == 3, "Refined pair drift"
    )
    scenario = [v for v in values if v["record"]["kind"] == "scenario_event"]
    require(sum(v["scenario"]["primary"] for v in scenario) == 3, "Primary scenario row drift")
    grouped = {}
    for row in scenario:
        grouped.setdefault(row["scenario"]["id"], []).append(row)
    require(
        len(grouped) == 3
        and all(
            sorted(v["scenario"]["position"] for v in rows) == [1, 2, 3]
            for rows in grouped.values()
        ),
        "Incomplete scenario",
    )
    return {
        "record_counts": dict(counts),
        "rule_counts": dict(rules),
        "refined_pairs": 3,
        "refined_hosts": 3,
        "primary_rows": 3,
        "scenario_triples": 3,
        "document_count": len(documents),
    }


def prepare(root=ROOT, client=request):
    p6, p7, p8, contract, scenario = prerequisites(root)
    before = live_state(client)
    ids = source_ids(p7, p8, scenario)
    lookup = event_lookup(
        fetch_evidence(ids, client, fields=EVIDENCE_FIELDS + ["windows_apt.original"])
    )
    require(set(lookup) == set(ids), "Missing source references")
    for row in p8["activity"]["event_rows"]:
        require(
            source_matches(row["detection_name"], lookup[row["event_id"]]),
            "Live detection evidence drift",
        )
    for saved in p7["windows"]["60"]["broad"]["tuples"]:
        shell, child = saved["event_ids"]
        require(
            lineage_pairs([lookup[shell]], [lookup[child]], 60) == [(shell, child)]
            and pair_record((shell, child), lookup) == saved,
            "Live pair evidence drift",
        )
    triples = verify_triples(p6, p7, lookup)
    require(
        triples == [scenario["primary"], *scenario["corroborating"]], "Scenario selection drift"
    )
    for event_id, projection in scenario["evidence"].items():
        require(source_projection(lookup[event_id]) == projection, "Scenario source evidence drift")
    documents = build_documents(p7, p8, scenario, lookup)
    require(live_state(client) == before, "Source index changed during preparation")
    manifest = {
        "passed": True,
        "presentation_index": INDEX,
        "source_index_pattern": "windows-apt-events-*",
        "source_state": {"counts": before[0], "mapping_sha256": before[1]},
        "source_event_ids_verified": len(ids),
        "source_event_ids_sha256": sha_json(ids),
        "presentation_source_event_ids": len(
            {i for d in documents.values() for i in d["source"]["event_ids"]}
        ),
        "source_projection_sha256": sha_json({i: source_projection(lookup[i]) for i in ids}),
        "documents_sha256": sha_json(documents),
        "counts": validate_documents(documents),
        "historical_time_range": TIME_RANGE,
        "timezone": "UTC",
        "units": UNITS,
        "input_sha256": {p: digest(root / p) for p in (EVALUATION, CONTRACT, SCENARIO)},
        "generator_sha256": digest(root / "scripts/build_dashboard_data.py"),
    }
    return documents, manifest


def mapping():
    keyword = {"type": "keyword", "ignore_above": 16384}

    def obj(names):
        return {"properties": {name: keyword for name in names.split()}}

    properties = {
        "@timestamp": {"type": "date_nanos"},
        "timestamp_exact": keyword,
        "record": obj("kind unit"),
        "host": obj("name"),
        "event": obj("id provider code"),
        "user": obj("name domain"),
        "source": obj("event_ids"),
        "analyst": obj("attack_id technique mapping_basis"),
        "detection": obj("id name"),
        "process": obj("name executable command_line entity_id"),
        "evidence": {
            "properties": {"category": keyword, "provenance": {"type": "object", "enabled": False}}
        },
        "service_evidence": {"type": "object", "enabled": False},
        "correlation": obj("id shell_event_id powershell_event_id relationship"),
        "scenario": obj("id role"),
    }
    properties["process"]["properties"]["parent"] = obj("name command_line entity_id")
    properties["correlation"]["properties"].update(
        {
            "refined": {"type": "boolean"},
            "start": {"type": "date_nanos"},
            "end": {"type": "date_nanos"},
            "gap_nanoseconds": {"type": "long"},
            "window_seconds": {"type": "integer"},
        }
    )
    properties["scenario"]["properties"].update(
        {
            "primary": {"type": "boolean"},
            "position": {"type": "integer"},
            "span_nanoseconds": {"type": "long"},
        }
    )
    return {"dynamic": "strict", "_meta": OWNER, "properties": properties}


def readback(client=request):
    response = client(
        f"/{INDEX}/_search",
        {"size": 2000, "track_total_hits": True, "query": {"match_all": {}}},
        method="POST",
    )
    hits = response["hits"]
    require(
        hits["total"]["relation"] == "eq" and hits["total"]["value"] == len(hits["hits"]),
        "Incomplete presentation readback",
    )
    return dict(sorted((h["_id"], h["_source"]) for h in hits["hits"]))


def index_documents(documents, client=request, bulk=http):
    current = client(f"/{INDEX}/_mapping", allow_missing=True)
    if current is None:
        client(
            f"/{INDEX}",
            {"settings": {"number_of_shards": 1, "number_of_replicas": 0}, "mappings": mapping()},
            method="PUT",
        )
    else:
        require(
            current[INDEX]["mappings"] == mapping(), "Presentation index ownership/mapping drift"
        )
        require(
            set(readback(client)) <= set(documents),
            "Unexpected existing presentation IDs; refusing overwrite",
        )
    body = "".join(
        json.dumps({"index": {"_id": key}}) + "\n" + json.dumps(value, ensure_ascii=False) + "\n"
        for key, value in documents.items()
    )
    result = bulk(f"/{INDEX}/_bulk?refresh=wait_for", body, "POST", service="presentation_bulk")
    require(
        result.get("errors") is False
        and len(result["items"]) == len(documents)
        and all(200 <= i["index"]["status"] < 300 for i in result["items"]),
        "Presentation bulk failure",
    )
    require(readback(client) == documents, "Indexed documents differ from deterministic source")


def run(root=ROOT):
    documents, manifest = prepare(root)
    index_documents(documents)
    state = live_state(request)
    require(
        state[0] == manifest["source_state"]["counts"]
        and state[1] == manifest["source_state"]["mapping_sha256"],
        "Source changed during indexing",
    )
    save_json(root / MANIFEST, manifest)
    print(json.dumps({"passed": True, "index": INDEX, **manifest["counts"]}))
    return manifest


if __name__ == "__main__":
    run()
