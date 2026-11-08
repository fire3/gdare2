"""Hand-rolled radare2-style argument parser."""

from __future__ import annotations

from dataclasses import dataclass, field

from gdare2.errors import UsageError

VALUE_FLAGS = frozenset("abcBeIikmpst")
BOOLEAN_FLAGS = frozenset("0A1E2fhjLnNqQSTuvVw")
DOUBLED = ("AA", "NN", "qq", "LL", "nn")
IGNORED = {
    "0": "output is never NUL-separated",
    "1": "use the shell's 2>&1 instead",
    "2": "use the shell's 2>&1 instead",
    "E": "edit the rc file directly",
    "f": "use `b $s` to set the block size",
    "k": "gdare2 does not do syscall resolution",
    "M": "use -e asm.demangle=false",
    "nn": "-n already covers this",
    "Q": "teardown saving is negligible",
    "S": "use -e cfg.sandbox=true",
    "t": "Ghidra analyses the project itself",
    "T": "Ghidra has no IDA-style hash cache",
    "u": "gdare2 does not filter symbol names",
}
# Ignored short options that still take a value in radare2.
IGNORED_VALUE = frozenset("k")

REJECTED = {
    "d": "the debugger is not implemented",
    "D": "the debugger is not implemented",
    "r": "there is no debugger to profile",
    "R": "there is no debugger to profile",
    "x": "load permissions come from Ghidra's loader",
    "X": "extraction plugins are not implemented",
    "P": "rapatch would write with different semantics",
}

LONG_VALUE = frozenset(
    {
        "attach",
        "status",
        "kill",
        "project",
        "project-name",
        "program",
        "ghidra-language",
        "compiler",
        "loader",
        "linger",
        "idle",
        "timeout",
        "startup-timeout",
        "assembler",
        "listen",
        "color",
        "endian",
    }
)
LONG_BOOL = frozenset(
    {
        "help",
        "version",
        "no-spawn",
        "save-on-close",
        "no-save-on-close",
        "sessions",
        "json",
        "force-language",
        "force-base",
        "wait",
        "ephemeral",
        "reimport",
        "allow-exec",
        "daemon-readonly",
    }
)


@dataclass
class Options:
    file: str | None = None
    commands: list[str] = field(default_factory=list)
    evals: list[tuple[str, str]] = field(default_factory=list)
    pre_scripts: list[str] = field(default_factory=list)
    post_scripts: list[str] = field(default_factory=list)
    ignored: list[tuple[str, str]] = field(default_factory=list)

    analyze: int = 0
    quiet: int = 0
    json: bool = False
    readonly: bool = True
    skip_rc: int = 0
    color: int | None = None
    seek: str | None = None

    arch: str | None = None
    bits: str | None = None
    base: str | None = None
    endian: str | None = None
    no_analysis: bool = False
    project: str | None = None
    project_name: str | None = None
    program: str | None = None
    ghidra_language: str | None = None
    compiler: str | None = None
    loader: str | None = None
    loader_args: list[tuple[str, str]] = field(default_factory=list)
    force_language: bool = False
    force_base: bool = False
    reimport: bool = False

    attach: str | None = None
    status: str | None = None
    kill: str | None = None
    spawn: bool = True
    linger: float | None = None
    idle: float | None = None
    timeout: float | None = None
    startup_timeout: float | None = None
    save_on_close: bool | None = None
    wait: bool = False
    assembler: str = "ghidra"
    daemon_readonly: bool = False
    ephemeral: bool = False
    allow_exec: bool = False
    listen: str | None = None

    show_help: bool = False
    show_version: int = 0
    list_sessions: bool = False

    @property
    def wants_database(self) -> bool:
        return not (
            self.show_help
            or self.show_version
            or self.list_sessions
            or self.kill
            or self.status
        )


def parse(argv: list[str]) -> Options:
    options = Options()
    index = 0
    only_positional = False
    while index < len(argv):
        token = argv[index]
        index += 1
        if only_positional or not token.startswith("-") or token == "-":
            _set_file(options, token)
            continue
        if token == "--":
            only_positional = True
            continue
        if token.startswith("--"):
            index = _long(options, token[2:], argv, index)
            continue
        index = _short(options, token[1:], argv, index)
    return options


def _set_file(options: Options, token: str) -> None:
    if options.file is not None:
        raise UsageError(f"only one file can be opened, got {options.file!r} and {token!r}")
    options.file = token


def _long(options: Options, body: str, argv: list[str], index: int) -> int:
    name, _, inline = body.partition("=")
    if name == "loader-arg":
        key = inline or _next(argv, index, "--loader-arg key")
        index += 0 if inline else 1
        value = _next(argv, index, "--loader-arg value")
        index += 1
        options.loader_args.append((key, value))
        return index
    if name in LONG_VALUE:
        value = inline or _next(argv, index, f"--{name}")
        index += 0 if inline else 1
        _apply_long_value(options, name, value)
        return index
    if name in LONG_BOOL:
        if inline:
            raise UsageError(f"--{name} does not take a value")
        _apply_long_bool(options, name)
        return index
    raise UsageError(f"unknown option --{name}")


def _apply_long_value(options: Options, name: str, value: str) -> None:
    if name == "attach":
        options.attach = value
    elif name == "status":
        options.status = value
    elif name == "kill":
        options.kill = value
    elif name == "project":
        options.project = value
    elif name == "project-name":
        options.project_name = value
    elif name == "program":
        options.program = value
    elif name == "ghidra-language":
        options.ghidra_language = value
    elif name == "compiler":
        options.compiler = value
    elif name == "loader":
        options.loader = value
    elif name == "linger":
        options.linger = _float(value, "--linger")
    elif name == "idle":
        options.idle = _float(value, "--idle")
    elif name == "timeout":
        options.timeout = _float(value, "--timeout")
    elif name == "startup-timeout":
        options.startup_timeout = _float(value, "--startup-timeout")
    elif name == "assembler":
        if value not in ("ghidra", "rasm2"):
            raise UsageError("--assembler must be ghidra or rasm2")
        if value == "rasm2":
            raise UsageError("--assembler=rasm2 is not implemented yet")
        options.assembler = value
    elif name == "listen":
        options.listen = value
    elif name == "color":
        options.color = _int(value, "--color")
    elif name == "endian":
        if value not in ("big", "little"):
            raise UsageError("--endian must be big or little")
        options.endian = value


def _apply_long_bool(options: Options, name: str) -> None:
    if name == "help":
        options.show_help = True
    elif name == "version":
        options.show_version = 1
    elif name == "no-spawn":
        options.spawn = False
    elif name == "save-on-close":
        options.save_on_close = True
    elif name == "no-save-on-close":
        options.save_on_close = False
    elif name == "sessions":
        options.list_sessions = True
    elif name == "json":
        options.json = True
    elif name == "force-language":
        options.force_language = True
    elif name == "force-base":
        options.force_base = True
    elif name == "wait":
        options.wait = True
    elif name == "ephemeral":
        options.ephemeral = True
    elif name == "reimport":
        options.reimport = True
    elif name == "allow-exec":
        raise UsageError("--allow-exec is not available until .gexec is implemented")
    elif name == "daemon-readonly":
        options.daemon_readonly = True


def _short(options: Options, cluster: str, argv: list[str], index: int) -> int:
    position = 0
    while position < len(cluster):
        doubled = cluster[position : position + 2]
        if doubled in DOUBLED:
            _apply_doubled(options, doubled)
            position += 2
            continue
        char = cluster[position]
        if char in REJECTED:
            raise UsageError(f"-{char} is not supported by gdare2: {REJECTED[char]}")
        if char in IGNORED:
            options.ignored.append((f"-{char}", IGNORED[char]))
            if char in IGNORED_VALUE:
                rest = cluster[position + 1 :]
                if rest:
                    return index
                index += 1
                _next(argv, index - 1, f"-{char}")
            position += 1
            continue
        if char == "-":
            break
        if char in VALUE_FLAGS:
            rest = cluster[position + 1 :]
            if rest:
                value = rest
            else:
                value = _next(argv, index, f"-{char}")
                index += 1
            _apply_short_value(options, char, value)
            return index
        if char in BOOLEAN_FLAGS:
            _apply_short_flag(options, char)
            position += 1
            continue
        raise UsageError(f"unknown option -{char}")
    return index


def _apply_doubled(options: Options, doubled: str) -> None:
    if doubled == "AA":
        options.analyze = 2
    elif doubled == "NN":
        options.skip_rc = 2
    elif doubled == "qq":
        options.quiet = 2
    elif doubled == "LL":
        options.list_sessions = True
    elif doubled == "nn":
        options.ignored.append(("-nn", IGNORED["nn"]))


def _apply_short_value(options: Options, char: str, value: str) -> None:
    if char == "a":
        options.arch = value
    elif char == "b":
        options.bits = value
    elif char in ("B", "m"):
        options.base = value
    elif char == "c":
        options.commands.append(value)
    elif char == "e":
        key, separator, setting = value.partition("=")
        if not separator:
            raise UsageError(f"-e expects key=value, got {value!r}")
        options.evals.append((key.strip(), setting.strip()))
    elif char == "i":
        options.post_scripts.append(value)
    elif char == "I":
        options.pre_scripts.append(value)
    elif char == "k":
        options.ignored.append(("-k", IGNORED["k"]))
    elif char == "p":
        options.project = value
    elif char == "s":
        options.seek = value
    elif char == "t":
        options.ignored.append(("-t", IGNORED["t"]))


def _apply_short_flag(options: Options, char: str) -> None:
    if char == "A":
        options.analyze = max(options.analyze, 1)
    elif char == "h":
        options.show_help = True
    elif char == "j":
        options.json = True
    elif char == "L":
        options.list_sessions = True
    elif char == "n":
        options.no_analysis = True
    elif char == "N":
        options.skip_rc = max(options.skip_rc, 1)
    elif char == "q":
        options.quiet = max(options.quiet, 1)
    elif char == "v":
        options.show_version = 1
    elif char == "V":
        options.show_version = 2
    elif char == "w":
        options.readonly = False


def _next(argv: list[str], index: int, what: str) -> str:
    if index >= len(argv):
        raise UsageError(f"{what} needs a value")
    return argv[index]


def _float(value: str, what: str) -> float:
    try:
        return float(value)
    except ValueError:
        raise UsageError(f"{what} needs a number, got {value!r}") from None


def _int(value: str, what: str) -> int:
    try:
        return int(value, 0)
    except ValueError:
        raise UsageError(f"{what} needs a number, got {value!r}") from None
