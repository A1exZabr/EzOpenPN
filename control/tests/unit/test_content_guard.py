from pathlib import Path

from tools.content_guard import scan_tree


def test_guard_rejects_constructed_historical_label(tmp_path: Path) -> None:
    value = "".join(chr(code) for code in (118, 112, 110))
    (tmp_path / "bad.txt").write_text(value, encoding="utf-8")

    assert scan_tree(tmp_path) == ["bad.txt: prohibited content"]


def test_guard_rejects_long_dash(tmp_path: Path) -> None:
    (tmp_path / "bad.md").write_text(chr(0x2014), encoding="utf-8")

    assert scan_tree(tmp_path) == ["bad.md: prohibited typography"]


def test_guard_accepts_neutral_copy(tmp_path: Path) -> None:
    (tmp_path / "ok.md").write_text("Защищённое подключение", encoding="utf-8")

    assert scan_tree(tmp_path) == []


def test_guard_checks_relative_file_names(tmp_path: Path) -> None:
    directory = tmp_path / "nested"
    directory.mkdir()
    historical_name = "".join(chr(code) for code in (1074, 1087, 1085))
    (directory / f"{historical_name}.md").write_text("neutral", encoding="utf-8")

    assert scan_tree(tmp_path) == [f"nested/{historical_name}.md: prohibited content"]


def test_guard_rejects_short_dash(tmp_path: Path) -> None:
    (tmp_path / "bad.md").write_text(chr(0x2013), encoding="utf-8")

    assert scan_tree(tmp_path) == ["bad.md: prohibited typography"]


def test_guard_skips_binary_files(tmp_path: Path) -> None:
    content = b"\x00" + bytes((118, 112, 110))
    (tmp_path / "image.bin").write_bytes(content)

    assert scan_tree(tmp_path) == []


def test_guard_rejects_literal_secret_assignment(tmp_path: Path) -> None:
    payload = 'password = "this must not be committed"\n'
    (tmp_path / "settings.py").write_text(payload, encoding="utf-8")

    assert scan_tree(tmp_path) == ["settings.py: possible secret"]
