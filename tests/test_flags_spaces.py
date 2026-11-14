"""Flag range/lookup commands (V9), flag spaces (V10) and snapshot spaces."""

from __future__ import annotations

import json

from test_session import make_session

from gdare2.errors import NotFoundError, UnsupportedError, UsageError

# --- V9: fc / fo / fd / fm ----------------------------------------------------


def test_fc_counts_current_space_and_lists_ranges():
    session, _ = make_session()
    assert session.run("fc") == ["3"]
    assert session.run("fc 0x1000 0x1000") == [
        "f entry 0 @ 0x0000000000001000",
        "f main 10 @ 0x0000000000001000",
    ]
    assert session.run("fc 0x2000 0x2000") == ["f helper 0 @ 0x0000000000002000"]
    assert session.run("fc 0x3000 0x4000") == []
    session.run("f extra 4 @ 0x7000")
    assert session.run("fc") == ["4"]


def test_fc_accepts_reversed_bounds_and_spans_spaces():
    session, _ = make_session()
    assert session.run("fc 0x2000 0x1000") == [
        "f entry 0 @ 0x0000000000001000",
        "f main 10 @ 0x0000000000001000",
        "f helper 0 @ 0x0000000000002000",
    ]
    session.run("fs imports")
    session.run("f imported 4 @ 0x6000")
    session.run("fs *")
    assert session.run("fc 0x5000 0x7000") == ["f imported 4 @ 0x0000000000006000"]


def test_fc_rejects_missing_bounds():
    session, _ = make_session()
    session.run("fc 0x1000")
    assert session.failed and isinstance(session.last_error, UsageError)


def test_fo_lists_flags_overlapping_the_range():
    session, _ = make_session()
    # main covers 0x1000..0x1009
    assert session.run("fo 0x1005 0x1008") == ["f main 10 @ 0x0000000000001000"]
    assert session.run("fo 0x1009 0x1009") == ["f main 10 @ 0x0000000000001000"]
    assert session.run("fo 0x100a 0x1fff") == []
    assert session.run("fo 0x2000 0x2000") == ["f helper 0 @ 0x0000000000002000"]
    session.run("f block 16 @ 0x1ff8")
    assert session.run("fo 0x2000 0x2004") == [
        "f block 16 @ 0x0000000000001ff8",
        "f helper 0 @ 0x0000000000002000",
    ]
    session.run("fo")
    assert session.failed and isinstance(session.last_error, UsageError)


def test_fd_resolves_flag_names_and_the_flag_at_seek():
    session, _ = make_session()
    assert session.run("fd entry") == ["0x0000000000001000"]
    assert session.run("fd helper") == ["0x0000000000002000"]
    session.run("s 0x2000")
    assert session.run("fd") == ["0x0000000000002000"]
    session.run("fd missing")
    assert session.failed and isinstance(session.last_error, NotFoundError)
    session.failed = False
    session.run("s 0x1f00")
    session.run("fd")
    assert session.failed and "no flag at" in str(session.last_error)


def test_fm_is_an_alias_of_bf():
    session, _ = make_session()
    assert session.run("fm main") == []
    assert session.blocksize == 10
    assert session.run("fm helper") == []
    assert session.blocksize == 1
    session.run("b 0x100")
    assert session.run("bf main") == []
    assert session.blocksize == 10
    session.run("fm missing")
    assert session.failed and isinstance(session.last_error, NotFoundError)


def test_f_unsupported_variants_are_explicit():
    session, _ = make_session()
    for cmd in ("fb", "fe", "ff", "fg", "fi", "fC", "fO", "fR", "fV"):
        session.run(cmd)
        assert session.failed, cmd
        assert isinstance(session.last_error, UnsupportedError), cmd
        assert "unknown or unsupported command" not in str(session.last_error), cmd
        session.failed = False
    session.run("fi")
    assert "fc and fo" in str(session.last_error)
    session.failed = False
    session.run("fC x")
    assert "CC" in str(session.last_error)
    session.failed = False
    session.run("fb")
    assert "f name @ addr" in str(session.last_error)


# --- V10: flag spaces ---------------------------------------------------------


def test_fs_lists_spaces_and_marks_the_current_one():
    session, _ = make_session()
    assert session.run("fs") == ["* *"]
    assert session.run("fs imports") == []
    assert session.flag_store.space == "imports"
    assert session.run("fs") == ["  *", "* imports"]
    session.run("f imported 4 @ 0x5000")
    assert [flag.name for flag in session.flag_store.values()] == ["imported"]
    assert session.run("fs *") == []
    assert session.flag_store.space == "*"
    assert [flag.name for flag in session.flag_store.values()] == [
        "entry",
        "main",
        "helper",
    ]


def test_fsj_and_fsq_report_spaces():
    session, _ = make_session()
    assert session.run("fsq") == ["*"]
    session.run("fs imports")
    assert session.run("fsq") == ["*", "imports"]
    assert json.loads(session.run("fsj")[0]) == {
        "current": "imports",
        "spaces": ["*", "imports"],
    }


def test_fs_star_is_replayable_and_restores_the_current_space():
    session, _ = make_session()
    session.run("fs imports")
    session.run("fs sections")
    session.run("fs imports")
    lines = session.run("fs*")
    assert lines == ["fs *", "fs sections", "fs imports"]
    replay, _ = make_session()
    for line in lines:
        replay.run(line)
    assert replay.flag_store.space == "imports"
    assert replay.run("fsq") == ["*", "imports", "sections"]


def test_fs_delete_is_strict():
    session, _ = make_session()
    session.run("fs scratch")
    assert session.run("fs- scratch") == []
    assert session.run("fsq") == ["*"]
    assert session.flag_store.space == "*"

    session.run("fs emptyspace")
    assert session.run("fs-") == []
    assert session.flag_store.space == "*"

    session.run("fs imports")
    session.run("f local 4 @ 0x5000")
    session.run("fs- imports")
    assert session.failed and "still holds flags" in str(session.last_error)
    session.failed = False
    session.run("fs- *")
    assert session.failed and "default" in str(session.last_error)
    session.failed = False
    session.run("fs- missing")
    assert session.failed and isinstance(session.last_error, NotFoundError)


def test_fsr_renames_spaces_and_moves_flags():
    session, _ = make_session()
    session.run("fs imports")
    session.run("f imported 4 @ 0x5000")
    assert session.run("fsr imports sections") == []
    assert session.flag_store.space == "sections"
    assert [flag.name for flag in session.flag_store.values()] == ["imported"]
    assert session.run("fsq") == ["*", "sections"]
    session.run("fs *")
    assert [flag.name for flag in session.flag_store.values()] == [
        "entry",
        "main",
        "helper",
    ]
    session.run("fs sections")
    assert session.run("fsr renamed") == []
    assert session.flag_store.space == "renamed"
    session.run("fsr missing other")
    assert session.failed and isinstance(session.last_error, NotFoundError)
    session.failed = False
    session.run("fsr")
    assert session.failed and isinstance(session.last_error, UsageError)


def test_f_listing_stays_space_scoped_while_lookup_is_global():
    session, _ = make_session()
    session.run("fs imports")
    session.run("f imported 4 @ 0x5000")
    assert session.run("fq") == ["imported"]
    assert session.run("f? entry") == ["1"]
    assert session.run("f? imported") == ["1"]
    session.run("fs *")
    assert session.run("fq") == ["entry", "main", "helper"]
    assert session.run("s imported") == []
    assert session.seek == 0x5000


# --- V10: project snapshot flag spaces ----------------------------------------


def test_project_snapshot_keeps_flag_spaces(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    session, _ = make_session()
    session.run("fs imports")
    session.run("f imported 4 @ 0x5000")
    session.run("fs *")
    session.run("f plain 8 @ 0x6000")

    payload = json.loads(session.run("Pj")[0])
    assert payload["version"] == 2
    assert {item["name"]: item["space"] for item in payload["flags"]} == {
        "imported": "imports",
        "plain": "*",
    }

    assert session.run("Ps demo")[0].startswith("-- saved ")
    fresh, _ = make_session()
    assert fresh.run("Po demo")[0].startswith("-- loaded ")
    assert fresh.flag_store.get("imported").space == "imports"
    assert fresh.flag_store.get("plain").space == "*"
    assert fresh.run("fsq") == ["*", "imports"]
    assert fresh.run("fs") == ["* *", "  imports"]


def test_v1_snapshot_flags_fall_back_to_the_default_space(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    project = tmp_path / "state" / "gdare2" / "projects" / "old.gdare2-prj"
    project.parent.mkdir(parents=True)
    project.write_text(
        json.dumps(
            {
                "version": 1,
                "seek": 0x1000,
                "blocksize": 256,
                "flags": [{"name": "legacy", "addr": 0x7000, "size": 4}],
            }
        ),
        encoding="utf-8",
    )
    session, _ = make_session()
    assert session.run("Po old")[0].startswith("-- loaded ")
    assert session.flag_store.get("legacy").space == "*"
    assert session.run("fq") == ["entry", "main", "helper", "legacy"]


def test_v10_snapshot_round_trip_restores_space_selection(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    session, _ = make_session()
    session.run("fs imports")
    session.run("f imported 4 @ 0x5000")
    assert session.run("Ps demo")[0].startswith("-- saved ")
    spaces = session.run("fs*")
    assert spaces == ["fs *", "fs imports"]
    replay, _ = make_session()
    replay.run("Po demo")
    for line in spaces:
        replay.run(line)
    assert replay.flag_store.space == "imports"
    assert [flag.name for flag in replay.flag_store.values()] == ["imported"]
