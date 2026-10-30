# Saved analysis and validation evidence

This directory contains generated evidence snapshots, not current setup instructions.
Use the [project README](../README.md) for reproduction order and the
[documentation guide](../docs/README.md) for the implemented design.

| Evidence | Meaning and current guide |
|---|---|
| [Dataset inventory](dataset_inventory.md), [ATT&CK coverage](attack_coverage.md), [ECS proposals](ecs_mapping_candidates.md) | Original inspection-stage findings; [dataset](../docs/dataset.md) and [implemented mappings](../docs/sanitization.md) explain their use |
| [Preprocessing report](preprocessing_report.md) | Row conservation, field coverage and timestamp decisions |
| [Ingestion report](ingestion/ingestion-report.md) | Recorded source-index validation; later detector prerequisite checks are saved separately under `detections/prerequisites/` |
| [Technique selection](technique_selection.md) | Evidence and rationale for the three implemented sub-techniques |
| [Detection report](detections/detection-report.md) | Thirteen query results, exact event sets and comparisons |
| [Correlation report](correlation/correlation-report.md) | Complete ordered pairs, EQL differences and service corroboration |
| [Scenario demonstration](scenarios/scenario-demonstration.md), [evaluation](evaluation/evaluation-report.md) | Bounded review and exact source evidence; see [evaluation guidance](../docs/evaluation.md) |
| [Dashboard report](dashboard/dashboard-report.md) | Recorded API/data/import and visual checks; see [dashboard guide](../docs/dashboard.md) |

## Interpreting historical wording

The original inspection reports use numbered phase names and say downstream features
are not implemented. Those statements describe the generation stage. Normalization,
ingestion, individual detections, correlation, scenario review and the dashboard are
now implemented. The early ECS proposals are research inputs; the current mapping
policy is documented in `docs/sanitization.md`.

Likewise, `dashboard_built: false` in the scenario contract describes the prerequisite
stage. The dashboard's own validation report records its implementation. Read each
artifact's recorded validation time and scope before using it as evidence of a run.

## Integrity and regeneration

Inventory, normalization, selection, detection, correlation and dashboard artifacts
form a chain of recorded hashes. Preserve their original bytes, including the explicit
line-ending exceptions in `.gitattributes`. Do not edit historical prose, counts or
hashes to make snapshots appear current. Regenerate affected outputs through their
documented commands after a source or implementation change, and validate downstream
consumers before claiming fresh success.

`analysis/inspection/` contains ignored caches that must be rebuilt on a fresh checkout.
The [detection runbook](../docs/individual-detection-implementation.md#reproduce)
includes the two required selection-cache commands. All values describe candidate
observations or structural relationships; no independent intent ground truth supports
accuracy or false-positive-rate claims.
