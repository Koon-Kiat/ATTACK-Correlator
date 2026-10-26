# Project scaffold and environment

This engineering record preserves the observations and checks for this workflow.
For the completed implementation and current status, see the [project README](../README.md).

Date: 2026-09-10. Scope: the initial project request's **"Begin with environment setup only"** instruction,
plus preparation of the ZIP supplied and then replaced with v4 during implementation.

## Completed work

- Initialized an empty Git repository on `main`; no commits or remote publication.
- Created the requested project layout, dataset placeholders and ignore rules.
- Added Python/Pandas inspection, safe ZIP preparation and publisher checksum tools.
- Created authenticated, version-matched Elastic Docker services, local Elasticsearch
  TLS, persistent volumes, health checks, and automatic Kibana account initialization.
- Added setup scripts for PowerShell and Bash and a credential-safe readiness check.
- Created the README, the requested workflow documentation and evidence-gated
  scaffolds for future mappings, detections, correlation, dashboard and evaluation.
- Prepared the current v4 ZIP: 28 members byte-verified after extraction and all
  20 publisher CSV checksums matched. Inspected the 20 CSVs completely.
- Moved the superseded extraction and reports outside active inputs to ignored
  `.local/superseded/`. Automatic approval review rejected deletion, so this cleanup
  preserves the old files. No active v4 source files were discarded.

## Files created

| Area | Files |
|---|---|
| Root | `README.md`, `docker-compose.yml`, `.env.example`, `.gitignore`, `.gitattributes`, `pyproject.toml`, `requirements.txt`, `requirements-dev.txt` |
| Dataset | `dataset/raw/.gitkeep`, `dataset/processed/.gitkeep`; ignored v4 extract |
| Python | `src/__init__.py`, `src/preprocessing/__init__.py`, `inspect_dataset.py`, pending `clean.py`, `normalize.py`, `enrich.py` |
| Scripts | `setup.ps1`, `setup.sh`, pending `ingest.ps1`, `ingest.sh`, `configure_env.py`, `prepare_dataset.py`, `verify_dataset.py`, `check_stack.py`, `create-certificates.sh`, `bootstrap-elastic.sh` |
| Elastic | `logstash/config/logstash.yml`, `logstash/pipeline/windows-apt.conf`, `elasticsearch/templates/README.md`, `kibana/README.md` |
| Detection/correlation | `detections/technique-{1,2,3}/README.md`, each slot's `detection.kql` and `detection.esql`; `correlation/README.md`, `correlation.eql`, `correlation.esql` |
| Analysis | `technique_selection.md`, `evaluation/README.md`, `inspection/.gitkeep`; ignored preparation, checksum and inspection reports |
| Tests | `test_configure_env.py`, `test_inspect_dataset.py`, `test_prepare_dataset.py`, `test_verify_dataset.py` |
| Documentation | `architecture.md`, `dataset.md`, `sanitization.md`, `detection-methodology.md`, `correlation.md`, `dashboard.md`, `evaluation.md`, `limitations.md`, this workflow record |

Generated `.env`, virtual environment, source data, inspection reports, test temporary
files, certificates and runtime state are not versioned. Python linting explicitly
excludes dataset and backup folders so publisher files remain unchanged.

## Verification evidence

- **29 automated tests passed**, covering benign fixtures, timestamps as observations,
  exact source/label preservation, JSON types and paths, nulls, malformed CSV/JSONL,
  duplicate preservation, deterministic output, partial scans, encoding failure,
  source-write protection, archive paths, byte preservation, checksums and secrets.
- Ruff lint and formatting checks passed; `pip check` reported no broken dependencies.
- Compose configuration validated. Initial startup completed successfully with
  Elasticsearch, Kibana and Logstash healthy and both initialization jobs exited zero.
- After Docker Desktop was found stopped, it was restarted and the saved Compose
  environment successfully started again. All three services were healthy on final
  verification. `analysis/inspection/stack-check.json` records the final readiness check.
- Logstash `--config.test_and_exit` returned **Configuration OK**. Both PowerShell
  scripts and all four Bash scripts passed syntax checks. PowerShell setup was rerun
  successfully and retained the existing `.env`.
- The readiness script observed Elasticsearch **9.5.3**, green cluster health,
  certificate-verified HTTPS and unauthenticated HTTP **401**; Kibana was available
  and Logstash's main pipeline was loaded. This verifies infrastructure only.
- Publisher checksums: **20/20**; independently rechecked all **28 extracted members**
  against the preparation manifest after development changes.
- Full v4 inspection: **20 CSVs**, all scans complete, zero structural parsing rejects.
  Combined log: **102,011 rows / 377 columns**; mapping supplement: **102,011 / 13**;
  scenario manifest: **36 / 8**; validation summary: **36 / 9**.
- Git ignore checks confirmed credentials, ZIPs, raw logs and superseded data are excluded.
- All local Markdown links resolved; the final scaffold contains 59 non-ignored files.

## Remaining work and limits

The main inspection report and dataset notes expose field candidates and actual source
spellings; they do not establish mapping semantics, reliable truth or technique occurrence.
No ECS mapping, ingestion, detection, correlation or dashboard has been implemented.
No techniques, attack sequence, screenshots, detection results or accuracy metrics
were fabricated. data normalization conversion and ECS tests remain tied to the future implementation.

dataset inspection must determine timestamp semantics, log/source roles, source overlap, observable
evidence, missing fields and the supplement's derived-label limitations. Its scenario
assignments cannot automatically be used as independent truth for technique evaluation.

The PowerShell environment is the native test host. Bash setup is supplied for
reproducibility; a complete fresh Linux/macOS Python installation has not been exercised.
Containerized Bash initialization was exercised on the Docker Linux engine.
