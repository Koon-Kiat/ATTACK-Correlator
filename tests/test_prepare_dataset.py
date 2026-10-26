from zipfile import ZipFile

import pytest

from scripts.prepare_dataset import prepare


def test_extract_preserves_all_bytes_and_refuses_overwrite(tmp_path):
    archive = tmp_path / "source.zip"
    with ZipFile(archive, "w") as bundle:
        bundle.writestr("dataset/example.csv", b"name\r\nlab\r\n")
    report = prepare(archive, tmp_path / "raw", tmp_path / "report.json")
    assert report["all_extracted_bytes_verified"]
    assert (tmp_path / "raw/dataset/example.csv").read_bytes() == b"name\r\nlab\r\n"
    with pytest.raises(ValueError, match="empty"):
        prepare(archive, tmp_path / "raw", tmp_path / "report.json")


@pytest.mark.parametrize(
    "member",
    ["../outside.csv", "/outside.csv", "C:/outside.csv", "..\\outside.csv", "dir./data.csv"],
)
def test_unsafe_archive_path_is_rejected_before_extraction(tmp_path, member):
    archive = tmp_path / "source.zip"
    with ZipFile(archive, "w") as bundle:
        bundle.writestr("valid.csv", "name\nlab\n")
        bundle.writestr(member, "name\nlab\n")
    with pytest.raises(ValueError, match="Unsafe"):
        prepare(archive, tmp_path / "raw", tmp_path / "report.json")
    assert not (tmp_path / "raw").exists()
