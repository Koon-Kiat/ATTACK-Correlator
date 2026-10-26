#!/usr/bin/env bash
set -euo pipefail
if [[ -s /certs/elasticsearch/elasticsearch.crt && -s /certs/elasticsearch/elasticsearch.key && -s /ca/ca.crt ]]; then
  echo "Existing local certificates retained."
  exit 0
fi
umask 077
work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT
bin/elasticsearch-certutil ca --silent --pem --out "$work_dir/ca.zip"
unzip -q "$work_dir/ca.zip" -d "$work_dir"
bin/elasticsearch-certutil cert --silent --pem \
  --name elasticsearch --dns elasticsearch,localhost --ip 127.0.0.1 \
  --ca-cert "$work_dir/ca/ca.crt" --ca-key "$work_dir/ca/ca.key" \
  --out "$work_dir/elasticsearch.zip"
unzip -qo "$work_dir/elasticsearch.zip" -d /certs
cp "$work_dir/ca/ca.crt" /certs/ca.crt
cp "$work_dir/ca/ca.crt" /ca/ca.crt
chown -R 1000:0 /certs /ca
find /certs /ca -type d -exec chmod 750 {} +
find /certs /ca -type f -exec chmod 640 {} +
echo "Local Elasticsearch certificate and public CA created."
