# Evaluation workspace

[Results](evaluation-results.json) and the [report](evaluation-report.md) contain the
bounded evidence review, separate event/pair/triple counts, exact refined activity
timestamps and qualitative coverage reasoning. The [dashboard contract](dashboard-contract.json)
identifies validated panel sources. Its `dashboard_built: false` records the prerequisite
stage; the implemented dashboard has its own [validation report](../dashboard/dashboard-report.md).

Use the [evaluation guide](../../docs/evaluation.md) for reproduction and interpretation.
Reviewed artifacts retain source/query
hashes, and temporary data belongs in ignored `results/`. No independent intent labels
or measured accuracy metrics are supplied. See [snapshot provenance](../README.md).
