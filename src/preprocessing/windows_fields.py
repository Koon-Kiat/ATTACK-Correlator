"""Observed v4 source columns and provisional semantic notes; no ECS transformations."""

P = "_source.data.win.eventdata."
S = "_source.data.win.system."
LABEL = "_source.rule.mitre.id"
NAMES = "_source.rule.mitre.technique"
TACTICS = "_source.rule.mitre.tactic"
GROUPS = {
    "event_metadata": [
        "_index",
        "_id",
        "_source.id",
        "_source.@timestamp",
        "_source.timestamp",
        S + "systemTime",
        S + "eventID",
        S + "providerName",
        S + "channel",
        "_source.decoder.name",
        "_source.location",
        "_source.input.type",
        "_source.rule.id",
        "_source.rule.description",
        "_source.full_log",
    ],
    "host": [
        "_source.agent.name",
        "_source.agent.id",
        "_source.agent.ip",
        S + "computer",
        "_source.manager.name",
        "_source.predecoder.hostname",
    ],
    "user_authentication": [
        P + name
        for name in [
            "user",
            "parentUser",
            "subjectUserName",
            "subjectDomainName",
            "subjectUserSid",
            "targetUserName",
            "targetDomainName",
            "targetUserSid",
            "logonId",
            "logonGuid",
            "logonType",
            "authenticationPackageName",
            "sourceUser",
            "targetUser",
        ]
    ]
    + ["_source.data.srcuser", "_source.data.dstuser", "_source.data.user"],
    "process": [
        P + name
        for name in [
            "image",
            "processName",
            "commandLine",
            "processId",
            "processGuid",
            "parentProcessId",
            "parentProcessGuid",
            "parentImage",
            "parentCommandLine",
            "sourceImage",
            "targetImage",
            "sourceProcessId",
            "targetProcessId",
            "sourceProcessGUID",
            "targetProcessGUID",
            "sourceProcessGuid",
            "targetProcessGuid",
            "grantedAccess",
            "imageLoaded",
            "utcTime",
        ]
    ],
    "file_registry": [
        P + name
        for name in [
            "targetFilename",
            "creationUtcTime",
            "hashes",
            "targetObject",
            "eventType",
            "details",
        ]
    ]
    + [
        "_source.syscheck." + name
        for name in [
            "path",
            "event",
            "mode",
            "changed_attributes",
            "mtime_before",
            "mtime_after",
            "md5_after",
            "sha1_after",
            "sha256_after",
            "sha256_before",
            "value_type",
        ]
    ],
    "network": [
        P + name
        for name in [
            "sourceIp",
            "sourcePort",
            "destinationIp",
            "destinationPort",
            "protocol",
            "ipAddress",
            "ipPort",
            "queryName",
            "sourceHostname",
            "destinationHostname",
        ]
    ],
    "attack_annotations": [
        LABEL,
        NAMES,
        TACTICS,
        "_source.rule.mitre_techniques",
        "_source.data.sca.check.compliance.mitre_techniques",
    ],
    "wmi_context": [P + name for name in ["name", "destination", "type", "operation", "consumer"]],
}

# Proposals are emitted only if the exact source column exists and has a real example.
ECS_CANDIDATES = [
    (
        S + "systemTime",
        "@timestamp",
        "Strong",
        "Windows event time includes Z; retain nanoseconds.",
    ),
    (
        "_source.@timestamp",
        "event.created (candidate)",
        "Moderate",
        "Displayed collection timestamp has no offset; establish its clock and timezone first.",
    ),
    (S + "computer", "host.name", "Strong", "Windows event's originating computer, not manager."),
    (
        "_source.agent.name",
        "agent.name",
        "Strong",
        "Collector-assigned agent name; do not silently equate to host.name.",
    ),
    (
        "_source.agent.id",
        "agent.id",
        "Strong",
        "Collector agent identifier, not a proven stable device ID.",
    ),
    (
        P + "user",
        "user.name + user.domain (split candidate)",
        "Moderate",
        "Process actor is domain-qualified; preserve raw escaping and "
        "separate components after review.",
    ),
    (
        P + "subjectUserName",
        "user.name (Security-event context)",
        "Moderate",
        "Security subject actor; targetUserName is a different role and must not overwrite it.",
    ),
    (
        P + "subjectDomainName",
        "user.domain (Security-event context)",
        "Moderate",
        "Domain of subject actor only.",
    ),
    (
        P + "image",
        "process.executable; process.name (derived basename)",
        "Strong",
        "Process image; validate escaping and non-path values such as System before deriving name.",
    ),
    (
        P + "commandLine",
        "process.command_line",
        "Strong",
        "Command line evidence; preserve quotes and backslashes.",
    ),
    (
        P + "processId",
        "process.pid",
        "Moderate",
        "Subject process ID; validate decimal/hex. system.processID is provider context.",
    ),
    (
        P + "processGuid",
        "process.entity_id",
        "Strong",
        "Sysmon process GUID supports identity beyond PID reuse.",
    ),
    (
        P + "parentProcessId",
        "process.parent.pid",
        "Moderate",
        "Parent process ID; validate numeric representation.",
    ),
    (
        P + "parentProcessGuid",
        "process.parent.entity_id",
        "Strong",
        "Parent GUID must be joined in host context.",
    ),
    (
        P + "parentImage",
        "process.parent.executable; process.parent.name (derived basename)",
        "Strong",
        "Parent image path; validate escaping.",
    ),
    (
        P + "parentCommandLine",
        "process.parent.command_line",
        "Strong",
        "Parent's command line, distinct from child arguments.",
    ),
    (
        P + "targetFilename",
        "file.path",
        "Strong",
        "Sysmon target file path; creation is an event fact, not inferred deletion.",
    ),
    (
        P + "hashes",
        "process.hash.* / dll.hash.* (event-dependent)",
        "Moderate",
        "Sysmon hashes describe process image or loaded module; not arbitrary file.hash.*.",
    ),
    (
        "_source.syscheck.sha256_after",
        "file.hash.sha256 (filesystem events only)",
        "Moderate",
        "Post-change checksum; syscheck can also refer to registry objects, "
        "which need separate semantics.",
    ),
    (
        P + "targetObject",
        "registry.path (registry-event context)",
        "Moderate",
        "Registry object path must not be forced into file.path.",
    ),
    (P + "sourceIp", "source.ip", "Strong", "Explicit source endpoint; validate IPv4/IPv6 syntax."),
    (P + "sourcePort", "source.port", "Strong", "Explicit source port; validate integer range."),
    (
        P + "destinationIp",
        "destination.ip",
        "Strong",
        "Explicit destination endpoint including loopback; do not assume external traffic.",
    ),
    (
        P + "destinationPort",
        "destination.port",
        "Strong",
        "Explicit destination port; validate integer range.",
    ),
    (
        P + "protocol",
        "network.transport",
        "Moderate",
        "Observed transport value; review spelling/case before later conversion.",
    ),
    (
        P + "queryName",
        "dns.question.name (DNS-event context)",
        "Moderate",
        "DNS query name only where provider/event semantics confirm it.",
    ),
    (
        S + "eventID",
        "event.code",
        "Strong",
        "Windows event code; retain provider/channel because codes overlap.",
    ),
    (S + "providerName", "event.provider", "Strong", "Observed Windows event provider."),
    (
        "_source.rule.id",
        "rule.id",
        "Strong",
        "Existing Wazuh rule identifier, not Windows event.code.",
    ),
    (
        "_source.full_log",
        "event.original (where present)",
        "Moderate",
        "Original message exists only for a subset; retain full CSV row provenance too.",
    ),
]
