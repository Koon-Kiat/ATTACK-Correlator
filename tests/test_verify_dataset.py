import hashlib

from scripts.verify_dataset import verify


def test_publisher_paths_and_mismatches(tmp_path):
    content = b"name\nlab\n"
    (tmp_path / "events.csv").write_bytes(content)
    expected = hashlib.sha256(content).hexdigest()
    (tmp_path / "checksums.sha256").write_text(f"{expected}  E:\\publisher\\events.csv\n")
    (tmp_path / "README.md").write_text("provenance")
    report = verify(tmp_path)
    assert report["checked"] == report["matched"] == 1
    assert report["not_covered"] == ["README.md"]
    (tmp_path / "events.csv").write_text("changed")
    assert verify(tmp_path)["matched"] == 0
