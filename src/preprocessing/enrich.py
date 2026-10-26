"""Disk-backed scenario joins and isolated publisher/Wazuh annotations."""

import json
import sqlite3

from src.preprocessing.clean import csv_rows, nonempty
from src.preprocessing.profile_values import extract_techniques
from src.preprocessing.windows_fields import LABEL, NAMES, TACTICS


def metadata_rows(path):
    result = []
    for _, _, _, row, _, error in csv_rows(path):
        if error:
            raise ValueError(f"Malformed metadata {path.name}: {error}")
        result.append(row)
    return result


def build_join(root, database):
    connection = sqlite3.connect(database)
    connection.execute(
        "CREATE TABLE mapping (source TEXT, n INTEGER, payload TEXT, PRIMARY KEY(source,n))"
    )
    count = 0
    try:
        for _, _, _, row, _, error in csv_rows(
            root / "scenario_mapping_supplement/log_to_scenario_mapping.csv"
        ):
            if error or not row.get("Row_Index", "").isdigit():
                raise ValueError("Invalid scenario mapping row")
            connection.execute(
                "INSERT INTO mapping VALUES (?,?,?)",
                (row["Source_CSV"], int(row["Row_Index"]), json.dumps(row)),
            )
            count += 1
        connection.commit()
        manifest = metadata_rows(root / "scenario_manifest.csv")
        validation = metadata_rows(root / "validation_summary.csv")
        if len({r["Scenrario_ID"] for r in manifest}) != len(manifest):
            raise ValueError("Duplicate manifest scenario ID")
        return connection, count, {"manifest": manifest, "validation": validation}
    except BaseException:
        connection.close()
        raise


def annotate(row, source, index, connection, known_scenarios):
    annotations = {}
    warnings = []
    attack = {}
    for field, target in [(LABEL, "ids"), (NAMES, "names"), (TACTICS, "tactics")]:
        if not nonempty(row.get(field, "")):
            continue
        try:
            values = json.loads(row[field])
            if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
                raise ValueError("Expected string array")
            if target == "ids" and any(extract_techniques(v) != {v} for v in values):
                raise ValueError("Invalid ATT&CK token")
            attack[target] = values  # Preserve order and duplicates; these are annotations.
        except ValueError:
            warnings.append({"field": field, "code": "invalid_annotation_array"})
    if attack:
        annotations["attack"] = attack
    wazuh = {
        k.removeprefix("_source.rule."): v
        for k, v in row.items()
        if k.startswith("_source.rule.") and v != ""
    }
    if wazuh:
        annotations["wazuh"] = wazuh
    fetched = connection.execute(
        "SELECT payload FROM mapping WHERE source=? AND n=?", (source, index)
    ).fetchone()
    scenario = None
    if fetched:
        mapping = json.loads(fetched[0])
        for target, origin in [
            ("Timestamp", "_source.@timestamp"),
            ("Agent_Name", "_source.agent.name"),
            ("MITRE_Technique", LABEL),
        ]:
            if mapping[target] != row.get(origin, ""):
                raise ValueError(f"Scenario join content mismatch: {source}:{index}:{target}")
        if mapping["Scenario_ID"] and mapping["Scenario_ID"] not in known_scenarios:
            raise ValueError("Unknown assigned scenario")
        scenario = {"source_mapping": mapping}
        for original, target in [
            ("Scenario_ID", "id"),
            ("Scenario_Name", "name"),
            ("Attribution_Strength", "attribution_strength"),
            ("Derived_Label", "derived_label"),
        ]:
            if nonempty(mapping[original]):
                scenario[target] = mapping[original]
        if mapping["Scenario_ID"]:
            scenario["metadata_ref"] = "publisher-metadata.json#" + mapping["Scenario_ID"]
    return annotations, scenario, warnings
