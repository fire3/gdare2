"""Packaging metadata must stay in sync with the import packages.

The version is single-sourced in ``src/gdare2/__init__.py`` and read by
hatchling, so ``pyproject.toml`` must not grow a second static version.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import gdare2

ROOT = Path(__file__).resolve().parents[1]


def _pyproject() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def _project() -> dict:
    return _pyproject()["project"]


def test_version_is_single_sourced() -> None:
    project = _project()
    assert project["name"] == "gdare2"
    assert project["dynamic"] == ["version"]
    assert "version" not in project
    assert gdare2.__version__


def test_console_scripts_and_packages_are_declared() -> None:
    project = _project()
    assert project["scripts"]["gdare2"] == "gdare2.cli:main"
    assert project["scripts"]["gdare2d"] == "gdare2d.__main__:main"

    wheel = _pyproject()["tool"]["hatch"]["build"]["targets"]["wheel"]
    assert wheel["packages"] == ["src/gdare2", "src/gdare2d"]


def test_runtime_dependency_and_python_floor() -> None:
    project = _project()
    assert project["requires-python"] == ">=3.11"
    assert "pyghidra>=3.2.0" in project["dependencies"]


def test_pep639_license_metadata() -> None:
    project = _project()
    assert project["license"] == "MIT"
    assert project["license-files"] == ["LICENSE"]
    assert "License :: OSI Approved :: MIT License" not in project["classifiers"]
    assert (ROOT / "LICENSE").is_file()


def test_pypi_badge_matches_the_package_version() -> None:
    svg = (ROOT / "assets" / "badges" / "pypi.svg").read_text(encoding="utf-8")
    assert f"v{gdare2.__version__}" in svg


def test_readme_uses_self_hosted_badges() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for name in ("pypi.svg", "python.svg", "license.svg"):
        assert f"assets/badges/{name}" in readme
    assert "actions/workflows/ci.yml/badge.svg" in readme
