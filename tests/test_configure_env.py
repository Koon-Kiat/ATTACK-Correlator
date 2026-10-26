from scripts.configure_env import configure


def test_secrets_are_random_and_never_overwritten_or_printed(tmp_path, capsys):
    (tmp_path / ".env.example").write_text("FIRST=GENERATE_ME\nSECOND=GENERATE_ME\nPORT=9200\n")
    assert configure(tmp_path)
    content = (tmp_path / ".env").read_text()
    first, second, port = content.splitlines()
    assert len(first.partition("=")[2]) == 64
    assert first.partition("=")[2] != second.partition("=")[2]
    assert port == "PORT=9200"
    assert not configure(tmp_path)
    assert (tmp_path / ".env").read_text() == content
    assert first.partition("=")[2] not in capsys.readouterr().out
