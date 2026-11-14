"""``gdare2 -V`` reporting must not need Ghidra, Java, or a daemon."""

from __future__ import annotations

import platform
import types
from importlib.metadata import PackageNotFoundError
from pathlib import Path

from gdare2 import PROTOCOL_VERSION, __version__, cli, versions

PROPERTIES = """\
application.name=Ghidra
application.release.name=PUBLIC
application.version=12.2
application.java.min=25
"""


def _install(root: Path, properties: str = PROPERTIES) -> Path:
    (root / "Ghidra").mkdir(parents=True)
    (root / "Ghidra" / "application.properties").write_text(properties, encoding="utf-8")
    return root


def test_ghidra_info_reads_properties_without_starting_a_jvm(tmp_path):
    root = _install(tmp_path / "ghidra_12.2_PUBLIC")

    info = versions.ghidra_info({"GHIDRA_INSTALL_DIR": str(root)}, home=tmp_path)

    assert info.available
    assert (info.version, info.release, info.java_min) == ("12.2", "PUBLIC", 25)
    assert info.root == root


def test_ghidra_info_uses_the_default_home_symlink_path(tmp_path):
    root = _install(tmp_path / "ghidra" / "current")

    info = versions.ghidra_info({}, home=tmp_path)

    assert info.available
    assert info.version == "12.2"
    assert info.root == root


def test_ghidra_info_reports_bad_install_and_missing_default(tmp_path):
    bad = versions.ghidra_info({"GHIDRA_INSTALL_DIR": str(tmp_path / "nope")}, home=tmp_path)
    missing = versions.ghidra_info({}, home=tmp_path / "empty")

    assert not bad.available
    assert "GHIDRA_INSTALL_DIR" in bad.error
    assert not missing.available
    assert "GHIDRA_INSTALL_DIR is not set" in missing.error


def test_java_executable_prefers_path_then_java_home(tmp_path, monkeypatch):
    from_path = tmp_path / "bin" / "java"
    from_path.parent.mkdir()
    from_path.write_text("", encoding="utf-8")
    from_path.chmod(0o755)

    monkeypatch.setattr(versions.shutil, "which", lambda name: str(from_path))
    assert versions.java_executable({"JAVA_HOME": str(tmp_path / "jdk")}) == from_path

    monkeypatch.setattr(versions.shutil, "which", lambda name: None)
    jdk = tmp_path / "jdk"
    (jdk / "bin").mkdir(parents=True)
    (jdk / "bin" / "java").write_text("", encoding="utf-8")
    (jdk / "bin" / "java").chmod(0o755)
    assert versions.java_executable({"JAVA_HOME": str(jdk)}) == jdk / "bin" / "java"


def test_java_version_parses_modern_and_legacy_versions(monkeypatch):
    def fake_run(command, **kwargs):
        return types.SimpleNamespace(stdout="", stderr='openjdk version "25.0.1" 2025-10-21\n')

    monkeypatch.setattr(versions.subprocess, "run", fake_run)
    assert versions.java_version("/fake/java") == "25.0.1"

    assert versions.java_major("25.0.1") == 25
    assert versions.java_major("1.8.0_402") == 8
    assert versions.java_major("") == 0


def test_version_lines_degrades_cleanly_without_ghidra_or_java(tmp_path, monkeypatch):
    monkeypatch.setattr(versions, "dist_version", lambda name: "9.9.9")
    monkeypatch.setattr(versions, "java_executable", lambda environ=None: None)

    lines = versions.version_lines({}, home=tmp_path / "empty")

    assert lines[0] == f"gdare2      {__version__} (protocol {PROTOCOL_VERSION})"
    assert lines[1] == "pyghidra    9.9.9"
    assert lines[2].startswith("ghidra      unavailable (")
    assert lines[3].startswith("java        unavailable (no java")
    assert lines[4] == f"python      {platform.python_version()}"


def test_version_lines_warns_when_java_is_too_old(tmp_path, monkeypatch):
    root = _install(tmp_path / "ghidra")
    monkeypatch.setattr(versions, "java_executable", lambda environ=None: Path("/fake/java"))
    monkeypatch.setattr(versions, "java_version", lambda executable: "21.0.5")

    lines = versions.version_lines({"GHIDRA_INSTALL_DIR": str(root)}, home=tmp_path)

    assert lines[2] == f"ghidra      12.2 PUBLIC ({root})"
    assert lines[3] == "java        21.0.5 (too old; Ghidra 12.2 needs Java 25+) at /fake/java"


def test_version_lines_reports_a_missing_pyghidra_distribution(tmp_path, monkeypatch):
    def missing(name):
        raise PackageNotFoundError(name)

    monkeypatch.setattr(versions, "dist_version", missing)
    monkeypatch.setattr(versions, "java_executable", lambda environ=None: None)

    lines = versions.version_lines({}, home=tmp_path)

    assert lines[1] == "pyghidra    unavailable (not installed)"


def test_cli_version_flags_do_not_need_a_target(capsys, monkeypatch):
    monkeypatch.setattr(cli, "version_lines", lambda: ["gdare2      test report"])

    assert cli.main(["-v"]) == 0
    assert capsys.readouterr().out == f"gdare2 {__version__}\n"

    assert cli.main(["-V"]) == 0
    assert capsys.readouterr().out == "gdare2      test report\n"
