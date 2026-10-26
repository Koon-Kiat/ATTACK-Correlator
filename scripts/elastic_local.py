"""Small Docker/curl client for the existing authenticated, TLS-verified local stack."""

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INDEX = "windows-apt-events-v1"
TEMPLATE = "windows-apt-events-template"


def compose(*args, input_text=None, env=None, timeout=60):
    result = subprocess.run(
        ["docker", "compose", *args],
        cwd=ROOT,
        input=input_text,
        capture_output=True,
        encoding="utf-8",
        env=env,
        timeout=timeout,
        check=False,
    )
    if result.returncode:
        # Avoid printing raw command output, which can include secrets or entire evidence.
        raise RuntimeError(f"Docker Compose {args[0]} failed; inspect local service logs")
    return result.stdout


def request(path, body=None, method="GET", allow_missing=False):
    if not path.startswith("/") or any(c in path for c in "\r\n'\""):
        raise ValueError("Invalid Elasticsearch request path")
    if method not in {"GET", "POST", "PUT", "DELETE"}:
        raise ValueError("Unsupported HTTP method")
    # Password expansion occurs inside the container, never in host argv or tool output.
    command = (
        'curl --silent --show-error --cacert config/certs/ca.crt -u "elastic:$ELASTIC_PASSWORD" '
        '-H "Content-Type: application/json" --max-time 60 -w "\\n%{http_code}" '
        f'-X {method} "https://localhost:9200{path}"'
    )
    if body is not None:
        command += " --data-binary @-"
    response = compose(
        "exec",
        "-T",
        "elasticsearch",
        "bash",
        "-c",
        command,
        input_text=None if body is None else json.dumps(body, ensure_ascii=False),
        timeout=75,
    )
    payload, _, status = response.rpartition("\n")
    if status == "404" and allow_missing:
        return None
    if not status.startswith("2"):
        error_type = json.loads(payload).get("error", {})
        if isinstance(error_type, dict):
            error_type = error_type.get("type", "request_error")
        raise RuntimeError(f"Elasticsearch {method} {path}: HTTP {status} ({error_type})")
    return json.loads(payload) if payload else {}


def service_json(service, path):
    if service == "kibana" and path == "/api/status":
        return json.loads(
            compose(
                "exec",
                "-T",
                "elasticsearch",
                "bash",
                "-c",
                'curl --silent --fail --max-time 15 -u "elastic:$ELASTIC_PASSWORD" '
                "http://kibana:5601/api/status",
            )
        )
    port = {"logstash": 9600, "kibana": 5601}[service]
    return json.loads(
        compose(
            "exec",
            "-T",
            service,
            "curl",
            "--silent",
            "--fail",
            "--max-time",
            "15",
            f"http://localhost:{port}{path}",
            timeout=30,
        )
    )


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
