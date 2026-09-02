from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PUBLIC_DOCUMENTS = (
    ROOT / "README.md",
    ROOT / "docs/getting-started.md",
    ROOT / "docs/profiles.md",
    ROOT / "docs/recovery.md",
    ROOT / "docs/troubleshooting.md",
    ROOT / "docs/security.md",
    ROOT / "docs/compatibility.md",
    ROOT / "docs/architecture.md",
    ROOT / "docs/releases/release-checklist.md",
)
INSTALL_COMMAND = (
    "curl -fsSL https://git.alexzabrodin.pro/ezopenpn/releases/latest/download/"
    "install.sh | sudo bash"
)
RESET_COMMAND = "sudo ezopenpn admin reset-password"
PROFILE_STEPS = (
    "Создайте профиль",
    "Установите совместимое приложение",
    "Отсканируйте QR-код или вставьте ссылку",
    "Переключите транспорт, если первый вариант нестабилен",
)


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _meaningful_paragraphs(value: str) -> list[str]:
    paragraphs: list[str] = []
    for raw in re.split(r"\n\s*\n", value):
        paragraph = " ".join(line.strip() for line in raw.splitlines()).strip()
        if paragraph and not paragraph.startswith("#"):
            paragraphs.append(paragraph)
    return paragraphs


def test_all_beginner_documents_exist() -> None:
    assert all(path.is_file() for path in PUBLIC_DOCUMENTS)


def test_readme_starts_with_clean_server_recommendation() -> None:
    paragraphs = _meaningful_paragraphs(_text(ROOT / "README.md"))
    assert "отдельный чистый VPS" in paragraphs[0]


def test_install_and_reset_commands_have_one_canonical_value() -> None:
    combined = "\n".join(_text(path) for path in PUBLIC_DOCUMENTS)
    install_commands = set(re.findall(r"curl -fsSL https://\S+install\.sh \| sudo bash", combined))
    reset_commands = set(re.findall(r"sudo ezopenpn admin reset-password", combined))
    assert install_commands == {INSTALL_COMMAND}
    assert reset_commands == {RESET_COMMAND}


def test_readme_names_supported_hosts_and_exact_ports() -> None:
    readme = _text(ROOT / "README.md")
    for system in ("Ubuntu 22.04", "Ubuntu 24.04", "Debian 12", "Debian 13"):
        assert system in readme
    for port in ("80/tcp", "443/tcp", "443/udp", "9443/tcp"):
        assert port in readme


def test_profile_help_has_the_same_four_steps_in_docs_and_panel() -> None:
    profile_docs = _text(ROOT / "docs/profiles.md")
    dashboard = _text(ROOT / "control/src/ezopenpn/web/templates/dashboard.html")
    profile_page = _text(ROOT / "control/src/ezopenpn/web/templates/profile.html")
    for step in PROFILE_STEPS:
        assert step in profile_docs
        assert step in dashboard
        assert step in profile_page
    assert profile_docs.count("data-profile-step") == 4
    assert dashboard.count("data-step=") == 4
    assert profile_page.count("data-step=") == 4


def test_panel_keeps_password_recovery_reminder_visible() -> None:
    dashboard = _text(ROOT / "control/src/ezopenpn/web/templates/dashboard.html")
    assert RESET_COMMAND in dashboard


def test_troubleshooting_covers_every_stable_installer_code() -> None:
    production = "\n".join(
        _text(path)
        for path in sorted((ROOT / "installer").rglob("*.sh"))
        if "/lab/" not in path.as_posix()
    )
    codes = set(re.findall(r"\bE_[A-Z0-9_]+\b", production))
    troubleshooting = _text(ROOT / "docs/troubleshooting.md")
    assert codes
    assert codes <= set(re.findall(r"\bE_[A-Z0-9_]+\b", troubleshooting))


def test_relative_markdown_links_resolve() -> None:
    link_pattern = re.compile(r"\[[^]]+\]\(([^)]+)\)")
    for document in PUBLIC_DOCUMENTS:
        for target in link_pattern.findall(_text(document)):
            if "://" in target or target.startswith("#"):
                continue
            relative = target.split("#", 1)[0]
            assert (document.parent / relative).resolve().exists(), (document, target)
