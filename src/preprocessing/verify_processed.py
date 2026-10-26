"""Stream a published Phase 3 release back against every verified canonical source row."""

import argparse
import json
from contextlib import ExitStack
from pathlib import Path

from src.preprocessing.clean import csv_rows, restore_row
from src.preprocessing.elastic_contract import validate_document
from src.preprocessing.preprocess import digest, provenance, verify_sources, write_json


def records(path):
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            yield json.loads(line)


def verify_processed(
    raw=Path("dataset/raw"), output=Path("dataset/processed"), analysis=Path("analysis")
):
    raw, output, analysis = raw.resolve(), output.resolve(), analysis.resolve()
    if analysis.is_relative_to(raw) or output.is_relative_to(raw):
        raise ValueError("Verification paths must be outside the raw tree")
    manifest = json.loads((analysis / "normalization-manifest.json").read_text(encoding="utf-8"))
    hashes = verify_sources(raw, manifest["phase2_source_sha256"])
    if digest(analysis / "inventory-manifest.json") != manifest["phase2_manifest_sha256"]:
        raise ValueError("Phase 2 manifest changed since preprocessing")
    for key, directory in [("processed_output_sha256", output), ("report_sha256", analysis)]:
        for name, expected in manifest[key].items():
            if digest(directory / name) != expected:
                raise ValueError(f"Phase 3 artifact hash mismatch: {name}")
    for name, expected in manifest["preprocessing_source_sha256"].items():
        if digest(Path(__file__).parent / name) != expected:
            raise ValueError(f"Preprocessing code changed: {name}")
    schemas = json.loads((output / "source-schemas.json").read_text(encoding="utf-8"))["headers"]
    mapping = json.loads((output / "elastic-mapping.json").read_text(encoding="utf-8"))
    processed = rejected = input_count = 0
    with ExitStack() as stack:
        events = records(output / "windows-apt-events.ndjson")
        stack.callback(events.close)
        rejects = (
            records(output / "rejected-events.ndjson")
            if manifest["counts"]["rejected_events"]
            else iter(())
        )
        if hasattr(rejects, "close"):
            stack.callback(rejects.close)
        event, reject = next(events, None), next(rejects, None)
        for source, headers in sorted(schemas.items()):
            for actual_headers, index, end_line, row, values, error in csv_rows(raw / source):
                input_count += 1
                if headers != actual_headers:
                    raise ValueError("Source header mismatch")
                expected_prov = provenance(row, source, index, end_line, hashes[source])
                if event is not None and event["windows_apt"]["provenance"] == expected_prov:
                    if error or restore_row(event["windows_apt"]["original"], headers) != row:
                        raise ValueError("Processed record does not reconstruct its source row")
                    validate_document(event, mapping)
                    processed += 1
                    event = next(events, None)
                elif reject is not None and reject["provenance"] == expected_prov:
                    if reject["parsed_csv_values"] != values or not reject["rejection_reason"]:
                        raise ValueError("Rejected record does not preserve its source row")
                    rejected += 1
                    reject = next(rejects, None)
                else:
                    raise ValueError(f"Unaccounted or reordered source record: {source}:{index}")
        if event is not None or reject is not None:
            raise ValueError("Unexpected extra output records")
    expected = manifest["counts"]
    if (input_count, processed, rejected) != (
        expected["input_events"],
        expected["processed_events"],
        expected["rejected_events"],
    ):
        raise ValueError("Output count mismatch")
    return {
        "input_events": input_count,
        "processed_events": processed,
        "rejected_events": rejected,
        "all_rows_accounted_for": input_count == processed + rejected,
        "all_original_rows_reconstructed": True,
        "raw_hashes_match": True,
        "output_and_report_hashes_match": True,
        "offline_mapping_contract_passed": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("dataset/raw"))
    parser.add_argument("--output", type=Path, default=Path("dataset/processed"))
    parser.add_argument("--analysis", type=Path, default=Path("analysis"))
    args = parser.parse_args()
    try:
        result = verify_processed(args.input, args.output, args.analysis)
        report = args.analysis / "inspection/normalization-verification.json"
        report.parent.mkdir(parents=True, exist_ok=True)
        write_json(report, result)
    except (OSError, ValueError, KeyError) as error:
        parser.exit(1, f"Processed verification failed: {error}\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
