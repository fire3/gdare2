# Releasing gdare2

The version lives in `src/gdare2/__init__.py` and is read by hatchling
(`[tool.hatch.version]`); `pyproject.toml` only declares it dynamically.

1. Update `__version__` and add a `CHANGELOG.md` entry.
2. Run the full local matrix:
   ```bash
   .venv/bin/python -m pytest -q
   GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/python -m pytest -q -m real_ghidra
   GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/python -m pytest -q -m parity
   GHIDRA_INSTALL_DIR=$HOME/ghidra/current .venv/bin/python -m pytest -q -m arch_matrix
   ruff check .
   ```
3. Build and inspect the artifacts:
   ```bash
   uv build
   uvx twine check dist/*
   ```
4. Commit, tag and push:
   ```bash
   git commit -am "release: vX.Y.Z"
   git tag vX.Y.Z
   git push origin main --tags
   ```
5. The `publish` workflow builds the sdist/wheel and uploads to PyPI through
   trusted publishing when a `v*` tag is pushed.  Configure the PyPI project's
   trusted publisher for this repository/workflow first; no API token is stored.
