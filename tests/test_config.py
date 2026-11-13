"""Typed configuration keys: defaults, coercion, readonly and reflection."""

from __future__ import annotations

import pytest

from gdare2.config import BOOL, INT, KEYS, Config
from gdare2.errors import UsageError


@pytest.mark.parametrize("key", KEYS, ids=lambda key: key.name)
def test_declared_defaults_are_visible(key):
    config = Config()
    assert config.get(key.name) == key.default
    assert key.name in dict(config.items())


@pytest.mark.parametrize(
    "text,expected",
    [
        ("true", True),
        ("TRUE", True),
        ("1", True),
        ("yes", True),
        ("on", True),
        ("false", False),
        ("0", False),
        ("no", False),
        ("off", False),
        ("", False),
    ],
)
def test_bool_coercion(text, expected):
    config = Config()
    config.set("scr.null", text)
    assert config.get_bool("scr.null") is expected


def test_int_coercion_accepts_hex_and_enforces_minimum():
    config = Config()
    config.set("hex.cols", "0x10")
    assert config.get_int("hex.cols") == 16
    with pytest.raises(UsageError, match="at least 1"):
        config.set("hex.cols", 0)
    with pytest.raises(UsageError, match="expected a number"):
        config.set("ghidra.timeout", "soon")


def test_string_and_unknown_keys():
    config = Config()
    config.set("search.in", "raw")
    assert config.get_str("search.in") == "raw"
    with pytest.raises(UsageError, match="unknown configuration key"):
        config.get("does.not.exist")
    with pytest.raises(UsageError, match="unknown configuration key"):
        config.set("does.not.exist", 1)
    with pytest.raises(UsageError, match="unknown configuration key"):
        config.reflect("does.not.exist", 1)


def test_readonly_keys_reject_writes_but_allow_reflection():
    config = Config()
    with pytest.raises(UsageError, match="read-only"):
        config.set("asm.arch", "arm")
    config.reflect("asm.arch", "arm")
    assert config.get_str("asm.arch") == "arm"
    assert "asm.arch" not in config.explicit


def test_explicit_tracks_cli_overrides():
    config = Config()
    assert config.explicit == set()
    config.set("scr.color", 2)
    assert config.explicit == {"scr.color"}


def test_every_kind_is_coerced():
    kinds = {key.kind for key in KEYS}
    assert kinds <= {BOOL, INT, "str"}
