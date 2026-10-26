import hashlib
import json
from pathlib import Path

import pytest

from src.preprocessing.inspect_dataset import inspect_dataset, main, timestamp_shape


def write(root: Path, name: str, content: str) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_absent_and_empty_dataset_are_pending(tmp_path):
    assert inspect_dataset(tmp_path / "absent")["status"] == "pending_dataset"
    write(tmp_path, ".gitkeep", "")
    report = inspect_dataset(tmp_path)
    assert report["status"] == "pending_dataset"
    assert report["files"] == []


def test_csv_preserves_strings_labels_and_source(tmp_path):
    # ATT&CK-shaped text here tests preservation only; it is not attack telemetry.
    source = write(
        tmp_path,
        "sample.csv",
        "host,label,ref,value\nlab,benign,T9999.001,001\nlab,NA,T9999,\nlab,null,,0\n",
    )
    before = source.read_bytes()
    report = inspect_dataset(tmp_path)["files"][0]
    assert report["records_examined"] == report["valid_records"] == 3
    assert report["fields"]["/value"]["observed_types"] == {"str": 2}
    assert report["fields"]["/value"]["empty_or_null_records"] == 1
    assert report["fields"]["/label"]["empty_or_null_records"] == 0
    assert report["fields"]["/ref"]["attack_id_text_occurrences"] == {
        "T9999": 1,
        "T9999.001": 1,
    }
    assert report["sha256"] == hashlib.sha256(before).hexdigest()
    assert source.read_bytes() == before


@pytest.mark.parametrize(
    "value,expected",
    [
        ("2025-01-02T03:04:05Z", "aware"),
        ("2025-01-02T11:04:05+08:00", "aware"),
        ("2025-01-02 03:04:05", "naive"),
        ("2025-99-02T03:04:05Z", None),
        ("1735787045", None),
        ("01/02/2025", None),
    ],
)
def test_timestamp_observation_does_not_guess_conversion(value, expected):
    assert timestamp_shape(value) == expected


def test_nested_json_paths_and_missing_values(tmp_path):
    write(
        tmp_path,
        "nested.json",
        json.dumps(
            [
                {
                    "host": {"name": "lab"},
                    "host.name": "literal",
                    "a/b": None,
                    "time": "2025-01-02T03:04:05Z",
                    "count": 7,
                    "ok": True,
                },
                {"host": {"name": None}, "count": 0, "items": ["benign", "T9999.001"]},
            ]
        ),
    )
    report = inspect_dataset(tmp_path)["files"][0]
    assert {"/host/name", "/host.name", "/a~1b"} <= report["fields"].keys()
    assert report["fields"]["/host/name"]["empty_or_null_records"] == 1
    assert report["fields"]["/host.name"]["absent_records"] == 1
    assert report["fields"]["/count"]["observed_types"] == {"int": 2}
    assert report["fields"]["/ok"]["observed_types"] == {"bool": 1}
    assert report["fields"]["/time"]["iso_timestamp_shapes"] == {"aware": 1}
    assert report["candidate_fields_by_name"]["timestamp"] == ["/time"]


def test_malformed_csv_is_counted_and_read_continues(tmp_path):
    write(tmp_path, "bad.csv", 'name,note\nlab,"two\nlines"\nshort\nlong,row,extra\nlast,ok\n')
    report = inspect_dataset(tmp_path)
    file = report["files"][0]
    assert report["status"] == "needs_review"
    assert file["valid_records"] == 2
    assert file["malformed_records"] == 2
    assert file["records_examined"] == 4
    assert file["diagnostics"][0]["location"] == 4
    assert file["scan_complete"]


@pytest.mark.parametrize("content", ["a,a\n1,2\n", 'a,b\n"unterminated,2\n', ""])
def test_fatal_csv_errors_are_explicit(tmp_path, content):
    write(tmp_path, "bad.csv", content)
    report = inspect_dataset(tmp_path)["files"][0]
    assert not report["scan_complete"]
    assert report["diagnostics"]


def test_jsonl_malformed_lines_and_duplicate_keys_are_reported(tmp_path):
    write(
        tmp_path,
        "records.ndjson",
        '{"ok":true}\ninvalid\n\n[1]\n{"a":1,"a":2}\n{"number":NaN}\n{"ok":false}\n',
    )
    report = inspect_dataset(tmp_path)["files"][0]
    assert report["records_examined"] == 7
    assert report["valid_records"] == 2
    assert report["malformed_records"] == 5
    assert report["fields"]["/ok"]["observed_types"] == {"bool": 2}


def test_duplicates_are_preserved_deterministically(tmp_path):
    write(tmp_path, "benign.jsonl", '{"name":"lab"}\n' * 501)
    first = inspect_dataset(tmp_path)
    assert first == inspect_dataset(tmp_path)
    assert first["files"][0]["valid_records"] == 501
    assert first["files"][0]["fields"]["/name"]["present_records"] == 501


def test_sample_counts_are_not_total_counts(tmp_path):
    write(tmp_path, "sample.csv", "name\na\nb\nc\n")
    report = inspect_dataset(tmp_path, max_records=2)
    assert report["status"] == "needs_review"
    assert report["files"][0]["records_examined"] == 2
    assert not report["files"][0]["scan_complete"]
    assert inspect_dataset(tmp_path, max_records=3)["files"][0]["scan_complete"]


def test_unsupported_files_and_json_size_limit_are_visible(tmp_path):
    write(tmp_path, "archive.zip", "not an archive; inventory test only")
    write(tmp_path, "large.json", '[{"name":"lab"}]')
    report = inspect_dataset(tmp_path, max_json_bytes=1)
    assert report["uninspected_files"] == ["archive.zip"]
    assert not report["files"][0]["scan_complete"]


def test_encoding_error_does_not_modify_source(tmp_path):
    path = tmp_path / "bad.csv"
    path.write_bytes(b"name\n\xff\n")
    report = inspect_dataset(tmp_path)["files"][0]
    assert not report["scan_complete"]
    assert path.read_bytes() == b"name\n\xff\n"


def test_header_only_csv_retains_observed_columns(tmp_path):
    write(tmp_path, "header.csv", "alpha,beta\n")
    file = inspect_dataset(tmp_path)["files"][0]
    assert set(file["fields"]) == {"/alpha", "/beta"}
    assert file["valid_records"] == 0


def test_cli_missing_dataset_writes_pending_report(tmp_path):
    output = tmp_path / "report.json"
    assert main(["--input", str(tmp_path / "raw"), "--output", str(output)]) == 2
    assert json.loads(output.read_text())["status"] == "pending_dataset"


def test_cli_refuses_to_write_inside_source(tmp_path):
    source = write(tmp_path, "original.json", '{"name":"lab"}')
    with pytest.raises(SystemExit) as error:
        main(["--input", str(tmp_path), "--output", str(source)])
    assert error.value.code == 2
    assert source.read_text() == '{"name":"lab"}'
