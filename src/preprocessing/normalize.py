"""Provider-aware ECS projection; original evidence and annotations are never rewritten."""

import re

from src.preprocessing.clean import (
    boolean,
    guid,
    integer,
    ip,
    nonempty,
    port,
    safe_text,
    utc_timestamp,
    windows_path,
)
from src.preprocessing.windows_fields import P, S

SYSMON = "Microsoft-Windows-Sysmon"
SECURITY = "Microsoft-Windows-Security-Auditing"
PROCESS_CODES = {
    "1",
    "2",
    "3",
    "5",
    "7",
    "11",
    "12",
    "13",
    "14",
    "15",
    "17",
    "18",
    "22",
    "23",
    "26",
}
FILE_CODES = {"2", "11", "15", "23", "26"}
REGISTRY_CODES = {"12", "13", "14"}


def put(document, path, value):
    parts = path.split(".")
    for part in parts[:-1]:
        document = document.setdefault(part, {})
    document[parts[-1]] = value


def normalize(row):
    output, warnings, mapping_warnings = {}, [], []

    def warn(field, code, mapping=False):
        (mapping_warnings if mapping else warnings).append({"field": field, "code": code})

    def project(field, target, convert=safe_text):
        value = row.get(field, "")
        if nonempty(value):
            try:
                put(output, target, convert(value))
            except ValueError:
                warn(field, "invalid_" + target.replace(".", "_"))

    def path(field, prefix, executable=False):
        value = row.get(field, "")
        if nonempty(value):
            try:
                parsed, name = windows_path(value, executable)
                if parsed is not None:
                    put(output, prefix + (".executable" if executable else ".path"), parsed)
                put(output, prefix + ".name", name)
            except ValueError:
                warn(field, "invalid_executable_path" if executable else "invalid_file_path")

    timestamp_quality = "unresolved"
    if nonempty(row.get(S + "systemTime", "")):
        try:
            output["@timestamp"] = utc_timestamp(row[S + "systemTime"])
            timestamp_quality = "explicit_utc"
        except ValueError:
            warn(S + "systemTime", "invalid_timestamp")
    for source, target in [
        (S + "computer", "host.name"),
        ("_source.agent.name", "agent.name"),
        ("_source.agent.id", "agent.id"),
        (S + "providerName", "event.provider"),
        ("_source.rule.id", "rule.id"),
    ]:
        project(source, target)
    project(S + "eventID", "event.code", lambda v: str(integer(v, 65535)))
    project("_source.full_log", "event.original", lambda v: v)
    provider = row.get(S + "providerName", "")
    code = output.get("event", {}).get("code")
    sysmon = provider == SYSMON
    process = sysmon and code in PROCESS_CODES
    access = sysmon and code in {"8", "10"}
    security_process = provider == SECURITY and code in {"4624", "4625"}
    if process:
        path(P + "image", "process", True)
        project(P + "processGuid", "process.entity_id", guid)
        project(P + "processId", "process.pid", lambda v: integer(v, 2**32 - 1))
    if access:
        path(P + "sourceImage", "process", True)
        project(P + "sourceProcessId", "process.pid", lambda v: integer(v, 2**32 - 1))
        aliases = [
            f
            for f in [P + "sourceProcessGUID", P + "sourceProcessGuid"]
            if nonempty(row.get(f, ""))
        ]
        if len({row[f].strip("{}").casefold() for f in aliases}) > 1:
            warn(P + "sourceProcessGUID/sourceProcessGuid", "conflicting_actor_guid_aliases", True)
        elif aliases:
            project(aliases[0], "process.entity_id", guid)
    if security_process:
        if row.get(P + "processName") != "-":
            path(P + "processName", "process", True)
        project(P + "processId", "process.pid", lambda v: integer(v, 2**32 - 1))
        if output.get("process", {}).get("pid") == 0:
            del output["process"]["pid"]
            warn(P + "processId", "unresolved_zero_security_pid", True)
    if sysmon and code == "1":
        project(P + "commandLine", "process.command_line", lambda v: v)
        path(P + "parentImage", "process.parent", True)
        project(P + "parentCommandLine", "process.parent.command_line", lambda v: v)
        project(P + "parentProcessGuid", "process.parent.entity_id", guid)
        project(P + "parentProcessId", "process.parent.pid", lambda v: integer(v, 2**32 - 1))
    for field in ["image", "processGuid", "processId"]:
        if (
            nonempty(row.get(P + field, ""))
            and not process
            and not (field == "processId" and security_process)
        ):
            warn(P + field, "unreviewed_process_context", True)
    if sysmon and code in FILE_CODES:
        path(P + "targetFilename", "file")
    elif nonempty(row.get(P + "targetFilename", "")):
        warn(P + "targetFilename", "unreviewed_file_context", True)
    if sysmon and code in REGISTRY_CODES:
        value = row.get(P + "targetObject", "")
        if nonempty(value):
            if re.match(r"^(?:HKLM|HKCU|HKU|HKCR|HKEY_[A-Z_]+)\\", value):
                project(P + "targetObject", "registry.path")
            else:
                warn(P + "targetObject", "invalid_registry_path")
    elif nonempty(row.get(P + "targetObject", "")):
        warn(P + "targetObject", "unreviewed_registry_context", True)
    if sysmon and code == "7":
        path(P + "imageLoaded", "dll")
    if sysmon and code == "3":
        for endpoint in ["source", "destination"]:
            project(P + endpoint + "Ip", endpoint + ".ip", ip)
            project(P + endpoint + "Port", endpoint + ".port", port)
        protocol = row.get(P + "protocol", "")
        if nonempty(protocol):
            if protocol.lower() in {"tcp", "udp", "icmp", "ipv6-icmp"}:
                put(output, "network.transport", protocol.lower())
            else:
                warn(P + "protocol", "invalid_transport")
    elif any(nonempty(row.get(P + f, "")) for f in ["sourceIp", "destinationIp"]):
        warn(P + "sourceIp/destinationIp", "unreviewed_network_context", True)
    if (sysmon and code == "22") or (provider == "Microsoft-Windows-DNS-Client" and code == "1014"):
        project(P + "queryName", "dns.question.name")
    elif nonempty(row.get(P + "queryName", "")):
        warn(P + "queryName", "unreviewed_dns_context", True)
    actor_field = P + "sourceUser" if access else P + "user"
    actor = row.get(actor_field, "") if process or access else ""
    if nonempty(actor) and actor != "-":
        components = re.split(r"\\+", actor)
        if len(components) == 2 and all(components):
            project(actor_field, "user.name", lambda _: safe_text(components[1]))
            project(actor_field, "user.domain", lambda _: safe_text(components[0]))
        elif len(components) == 1:
            project(actor_field, "user.name")
        else:
            warn(actor_field, "ambiguous_actor_user", True)
    if provider == SECURITY:
        for source, target in [
            ("subjectUserName", "name"),
            ("subjectDomainName", "domain"),
            ("subjectUserSid", "id"),
        ]:
            if row.get(P + source) != "-":
                project(P + source, "user." + target)
    hash_value = row.get(P + "hashes", "")
    if nonempty(hash_value):
        target = (
            "process.hash"
            if sysmon and code == "1"
            else "dll.hash"
            if sysmon and code == "7"
            else None
        )
        if target:
            parsed, invalid = parse_hashes(hash_value)
            if parsed:
                put(output, target, parsed)
            for reason in invalid:
                warn(P + "hashes", reason)
        else:
            warn(P + "hashes", "unreviewed_hash_object", True)
    for source, name in [
        ("initiated", "initiated"),
        ("signed", "signed"),
        ("sourceIsIpv6", "source_is_ipv6"),
        ("destinationIsIpv6", "destination_is_ipv6"),
    ]:
        if sysmon:
            project(P + source, "windows_apt.observed.flags." + name, boolean)
    for field, value in row.items():
        if any(ord(c) < 32 and c not in "\r\n\t" for c in value):
            warn(field, "control_characters_preserved_in_original")
    quality = {"timestamp": timestamp_quality}
    if warnings:
        quality["normalization_warnings"] = sorted(warnings, key=lambda x: (x["field"], x["code"]))
    if mapping_warnings:
        quality["mapping_warnings"] = sorted(
            mapping_warnings, key=lambda x: (x["field"], x["code"])
        )
    put(output, "windows_apt.quality", quality)
    return output


def parse_hashes(value):
    lengths = {"MD5": 32, "SHA1": 40, "SHA256": 64, "SHA512": 128}
    parsed, warnings, conflicted = {}, set(), set()
    for entry in value.split(","):
        algorithm, separator, digest = entry.strip().partition("=")
        algorithm = algorithm.upper()
        if algorithm == "IMPHASH":
            continue  # PE-specific field retained in original; not a generic ECS hash.
        if not separator or algorithm not in lengths:
            warnings.add("unmapped_hash_algorithm")
            continue
        key = algorithm.lower()
        if not re.fullmatch(r"[a-fA-F0-9]{" + str(lengths[algorithm]) + "}", digest):
            warnings.add("invalid_hash")
        elif key in parsed and parsed[key] != digest.lower():
            conflicted.add(key)
            warnings.add("conflicting_hash_values")
        elif key not in conflicted:
            parsed[key] = digest.lower()
    return {k: v for k, v in parsed.items() if k not in conflicted}, sorted(warnings)
