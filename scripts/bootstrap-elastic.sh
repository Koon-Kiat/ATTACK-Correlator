#!/usr/bin/env bash
set -euo pipefail
# configure_env.py generates hexadecimal values; reject unsafe manual substitutions.
if [[ ! "$KIBANA_PASSWORD" =~ ^[a-zA-Z0-9]{32,}$ ]]; then
  echo "KIBANA_PASSWORD must contain at least 32 alphanumeric characters." >&2
  exit 1
fi
printf '{"password":"%s"}' "$KIBANA_PASSWORD" |
  curl --silent --show-error --fail --cacert /ca/ca.crt \
    -u "elastic:$ELASTIC_PASSWORD" -H 'Content-Type: application/json' \
    -X POST https://elasticsearch:9200/_security/user/kibana_system/_password \
    --data-binary @- >/dev/null
echo "Kibana service account configured. No dataset mappings or rules installed."
