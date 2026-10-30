# Documentation guide

The [project README](../README.md) gives the setup and reproduction order. These guides
describe the implemented local pipeline, pinned to Elastic 9.5.3. Documentation was
reviewed against the source and saved evidence on 30 October 2026; that review is not
a new live Elasticsearch, Kibana or browser validation.

| Task | Guide |
|---|---|
| Understand components and data flow | [Architecture](architecture.md) |
| Acquire and inspect the correct corpus | [Dataset preparation](dataset.md) |
| Understand preservation, timestamps and ECS fields | [Sanitization](sanitization.md) |
| Ingest, validate and troubleshoot the source index | [Elastic ingestion](elastic-ingestion-and-validation.md) |
| Understand the three selected strategies | [Detection methodology](detection-methodology.md) |
| Run individual detections and rebuild prerequisites | [Detection runbook](individual-detection-implementation.md) |
| Understand joins, windows and evidence units | [Correlation methodology](correlation.md) |
| Execute and verify historical correlation | [Correlation runbook](event-correlation-validation.md) |
| Build the bounded scenario and interpret the review | [Evaluation](evaluation.md) |
| Read the dashboard's panels, units and filters | [Dashboard guide](dashboard.md) |
| Build and validate the dashboard | [Dashboard runbook](kibana-dashboard-implementation.md) |
| Import the saved dashboard | [Kibana export guide](../kibana/README.md) |
| Check analytical and operational limits | [Limitations](limitations.md) |
| Render reports and package current files | [Release preparation](release-preparation.md) |

## Evidence and historical records

[Analysis artifacts](../analysis/README.md) retain the observations, exact IDs, query
results, timestamps and hashes from their recorded runs. Several early generated
reports describe an inspection stage before downstream features existed; use this
guide and the project README for current implementation status. Do not hand-edit
hash-linked reports or relabel old checks as new validation.

Superseded scaffold, inspection, normalization, selection and scenario progress logs
have been removed. Their maintained guidance is in the guides above; the underlying
analysis artifacts remain available. Operational runbooks retain their existing paths
because generated reports link to them.
