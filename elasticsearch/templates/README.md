# Event index template

`windows-apt-events-template.json` is generated and installed by `scripts/ingest.py`
after full data normalization verification. It wraps the unchanged
`dataset/processed/elastic-mapping.json` contract: strict fields, `date_nanos`, ECS types
and disabled parsing for original evidence payloads. Settings are one primary shard,
zero replicas and template priority 200, matching `windows-apt-events-*`.

The target `windows-apt-events-v1` is a normal index so unresolved events can omit
`@timestamp`. Template updates do not rewrite existing mappings: a conflicting target
mapping stops ingestion and requires investigation. Normal runs never delete data.
See [ingestion validation](../../docs/elastic-ingestion-and-validation.md) and the
[live validation report](../../analysis/ingestion/ingestion-report.md).
