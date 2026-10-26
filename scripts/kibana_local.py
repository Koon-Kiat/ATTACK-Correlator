"""Authenticated local Kibana API and presentation-only bulk client.

Credentials expand inside the existing container, never in host argv or reports.
"""

import json
import re

from scripts.elastic_local import compose


def http(
    path, body=None, method="GET", *, service="kibana", raw=False, missing=False, multipart=False
):
    if not re.fullmatch(r"/[a-zA-Z0-9_/*?.=&%:-]*", path):
        raise ValueError("Invalid local API path")
    if method not in {"GET", "POST", "PUT", "DELETE"}:
        raise ValueError("Unsupported HTTP method")
    if service == "kibana":
        base, tls = "http://kibana:5601", ""
    elif (
        service == "presentation_bulk"
        and path == "/attack-correlator-dashboard-v1/_bulk?refresh=wait_for"
    ):
        base, tls = "https://localhost:9200", "--cacert config/certs/ca.crt"
    else:
        raise ValueError("Only presentation bulk writes are allowed")
    content_type = "application/x-ndjson" if service == "presentation_bulk" else "application/json"
    header = "" if multipart else f'-H "Content-Type: {content_type}"'
    command = (
        f'curl --silent --show-error {tls} -u "elastic:$ELASTIC_PASSWORD" '
        f'{header} -H "kbn-xsrf: true" --max-time 60 -w "\\n%{{http_code}}" '
        f'-X {method} "{base}{path}"'
    )
    payload = body if isinstance(body, str) else json.dumps(body, ensure_ascii=False)
    if body is not None:
        command += (
            ' -F "file=@-;filename=dashboard.ndjson;type=application/x-ndjson"'
            if multipart
            else " --data-binary @-"
        )
    response = compose(
        "exec",
        "-T",
        "elasticsearch",
        "bash",
        "-c",
        command,
        input_text=payload if body is not None else None,
        timeout=75,
    )
    value, _, status = response.rpartition("\n")
    if status == "404" and missing:
        return None
    if not status.startswith("2"):
        # API errors can contain supplied evidence. Keep diagnostics bounded.
        error = json.loads(value)
        detail = str(error.get("message", error.get("error", "request_error")))[:1500]
        raise RuntimeError(f"Local {service} {method} {path}: HTTP {status}: {detail}")
    return value if raw else json.loads(value) if value else {}


def kibana(path, body=None, method="GET", *, space=None, **kwargs):
    if space is not None:
        if not re.fullmatch(r"[a-z0-9-]+", space):
            raise ValueError("Invalid space ID")
        path = f"/s/{space}{path}"
    return http(path, body, method, **kwargs)
