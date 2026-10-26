"""Verify local service readiness without exposing credentials or adding dataset events."""

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def execute(service: str, command: list[str]) -> str:
    result = subprocess.run(
        ["docker", "compose", "exec", "-T", service, *command],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(f"{service} readiness request failed; inspect Compose service logs")
    return result.stdout.strip()


def check() -> dict:
    # Only the container shell expands the password. It is not printed or placed in host argv.
    es_request = (
        "curl --silent --show-error --fail --cacert config/certs/ca.crt "
        '-u "elastic:$ELASTIC_PASSWORD" '
    )
    es = json.loads(execute("elasticsearch", ["bash", "-c", es_request + "https://localhost:9200"]))
    health = json.loads(
        execute(
            "elasticsearch",
            [
                "bash",
                "-c",
                es_request + "https://localhost:9200/_cluster/health",
            ],
        )
    )
    unauthenticated = execute(
        "elasticsearch",
        [
            "curl",
            "--silent",
            "--cacert",
            "config/certs/ca.crt",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "https://localhost:9200",
        ],
    )
    kibana = json.loads(
        execute(
            "kibana",
            [
                "curl",
                "--silent",
                "--fail",
                "http://localhost:5601/api/status",
            ],
        )
    )
    logstash = json.loads(
        execute(
            "logstash",
            [
                "curl",
                "--silent",
                "--fail",
                "http://localhost:9600/_node/pipelines/main",
            ],
        )
    )
    if health["status"] not in {"green", "yellow"} or unauthenticated != "401":
        raise RuntimeError("Elasticsearch health or authentication check failed")
    if kibana["status"]["overall"]["level"] != "available":
        raise RuntimeError("Kibana is not available")
    if "main" not in logstash["pipelines"]:
        raise RuntimeError("Logstash main pipeline is not loaded")
    return {
        "elasticsearch_version": es["version"]["number"],
        "elasticsearch_health": health["status"],
        "elasticsearch_tls_verified": True,
        "unauthenticated_elasticsearch_status": 401,
        "kibana_status": "available",
        "logstash_main_pipeline": "loaded",
        "scope": "Infrastructure only; no dataset ingestion or detection validation",
    }


if __name__ == "__main__":
    try:
        print(json.dumps(check(), indent=2))
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        raise SystemExit(str(error)) from None
