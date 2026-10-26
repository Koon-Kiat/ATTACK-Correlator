"""Offline mapping contract for Phase 4; no Elasticsearch connection or ingestion."""

import ipaddress

from src.preprocessing.clean import utc_timestamp


def mapping_contract():
    properties = {}

    def add(path, kind, **options):
        cursor = properties
        parts = path.split(".")
        for name in parts[:-1]:
            cursor = cursor.setdefault(name, {"properties": {}})["properties"]
        cursor[parts[-1]] = {"type": kind, **options}

    add("@timestamp", "date_nanos", format="strict_date_optional_time_nanos")
    for field in [
        "event.id",
        "event.code",
        "event.provider",
        "host.name",
        "agent.id",
        "agent.name",
        "rule.id",
        "user.name",
        "user.domain",
        "user.id",
        "network.transport",
        "dns.question.name",
        "process.name",
        "process.entity_id",
        "process.parent.name",
        "process.parent.entity_id",
        "file.name",
        "dll.name",
        "windows_apt.quality.timestamp",
        "windows_apt.provenance.source_file",
        "windows_apt.provenance.source_sha256",
        "windows_apt.provenance.original_index",
        "windows_apt.provenance.original_id",
        "windows_apt.provenance.source_representation",
        "windows_apt.provenance.dataset",
        "windows_apt.provenance.dataset_version",
        "windows_apt.provenance.processing_version",
        "windows_apt.provenance.row_sha256",
        "windows_apt.annotations.attack.ids",
        "windows_apt.annotations.attack.names",
        "windows_apt.annotations.attack.tactics",
        "windows_apt.scenario.id",
        "windows_apt.scenario.name",
        "windows_apt.scenario.metadata_ref",
        "windows_apt.scenario.attribution_strength",
        "windows_apt.scenario.derived_label",
    ]:
        add(field, "keyword", ignore_above=1024)
    for field in [
        "process.executable",
        "process.command_line",
        "process.parent.executable",
        "process.parent.command_line",
        "file.path",
        "dll.path",
        "registry.path",
    ]:
        add(field, "wildcard")
    add("event.original", "keyword", index=False, doc_values=False)
    for field in [
        "process.pid",
        "process.parent.pid",
        "source.port",
        "destination.port",
        "windows_apt.provenance.source_row_index",
        "windows_apt.provenance.csv_record_end_line",
    ]:
        add(field, "long")
    for field in ["source.ip", "destination.ip"]:
        add(field, "ip")
    for target in ["process", "dll"]:
        for algorithm in ["md5", "sha1", "sha256", "sha512"]:
            add(f"{target}.hash.{algorithm}", "keyword", ignore_above=128)
    for name in ["signed", "initiated", "source_is_ipv6", "destination_is_ipv6"]:
        add("windows_apt.observed.flags." + name, "boolean")
    for name in ["normalization_warnings", "mapping_warnings"]:
        for part in ["field", "code"]:
            add("windows_apt.quality." + name + "." + part, "keyword", ignore_above=1024)
    for name in ["original", "annotations.wazuh", "scenario.source_mapping"]:
        add("windows_apt." + name, "object", enabled=False)
    return {"dynamic": "strict", "properties": properties}


def validate_document(document, mapping=None, prefix=""):
    """Check emitted shapes/types against the offline contract, not server behaviour."""
    mapping = mapping or mapping_contract()
    for name, value in document.items():
        path = prefix + name
        spec = mapping["properties"].get(name)
        if spec is None:
            raise ValueError(f"Unmapped output field: {path}")
        if spec.get("enabled") is False:
            continue
        for item in value if isinstance(value, list) else [value]:
            if "properties" in spec:
                if not isinstance(item, dict):
                    raise ValueError(f"Expected object at {path}")
                validate_document(item, spec, path + ".")
            elif spec["type"] == "long":
                if type(item) is not int or not -(2**63) <= item < 2**63:
                    raise ValueError(f"Invalid long at {path}")
            elif spec["type"] == "boolean":
                if type(item) is not bool:
                    raise ValueError(f"Invalid boolean at {path}")
            else:
                if not isinstance(item, str):
                    raise ValueError(f"Expected string at {path}")
                if spec["type"] == "ip":
                    ipaddress.ip_address(item)
                if spec["type"] == "date_nanos":
                    utc_timestamp(item)
