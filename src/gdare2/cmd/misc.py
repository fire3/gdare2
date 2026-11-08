"""Script, variable and last-output commands."""

from __future__ import annotations

from pathlib import Path

from gdare2.cmd import command
from gdare2.errors import GdarError, UsageError


@command("S", "run a command script")
def _script(session, statement):
    path = statement.args.strip()
    if not path:
        raise UsageError("S needs a script file")
    try:
        lines = Path(path).expanduser().read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise GdarError(f"cannot read script {path}: {exc}") from exc
    output: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        output.extend(session.run(stripped))
        if session.quit_requested:
            break
    return output


@command("$", "get or set a session variable")
def _variable(session, statement):
    text = statement.cmd[1:]
    if statement.args:
        text = f"{text} {statement.args}".strip()
    text = text.strip()
    if not text or text in ("?", "*"):
        return [f"${name} = {value}" for name, value in sorted(session.vars.items())]
    if "=" in text:
        name, _, value = text.partition("=")
        name = name.strip().lstrip("$")
        if not name:
            raise UsageError("$ needs a variable name")
        session.vars[name] = session.eval(value.strip())
        return []
    name = text.lstrip("$")
    if name not in session.vars:
        raise GdarError(f"variable ${name} is not set")
    return [str(session.vars[name])]


@command("_", "print the last command output")
def _last_output(session, statement):
    return list(session.last_output)
