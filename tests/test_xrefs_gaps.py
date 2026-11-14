"""V14: ax* xref command gap coverage (axg, axF, ax., axq, ax, axv, axff, axH, write stubs)."""

from __future__ import annotations

import json

from test_session import FakeClient, make_session

from gdare2.errors import NotFuncError


class XrefClient(FakeClient):
    """FakeClient over a small call graph.

    fcn.main (0x1000-0x103f) and fcn.helper (0x2000-0x203f) both call
    fcn.helper / fcn.leaf (0x3000-0x303f); 0x4000 is raw data with no function.
    """

    FUNCTIONS = (
        (0x1000, "fcn.main"),
        (0x2000, "fcn.helper"),
        (0x3000, "fcn.leaf"),
    )
    SIZE = 0x40

    def call(self, op, **args):
        if op == "xrefs_to":
            self.calls.append((op, args))
            return {
                0x1000: [{"from": 0x4000, "to": 0x1000, "type": "DATA"}],
                0x2000: [
                    {"from": 0x1010, "to": 0x2000, "type": "CALL"},
                    {"from": 0x1018, "to": 0x2000, "type": "CALL"},
                ],
                0x3000: [{"from": 0x2010, "to": 0x3000, "type": "CALL"}],
            }.get(int(args["ea"]), [])
        if op == "xrefs_from":
            self.calls.append((op, args))
            return {
                0x1000: [{"from": 0x1000, "to": 0x2000, "type": "CALL"}],
            }.get(int(args["ea"]), [])
        if op == "xrefs_all":
            self.calls.append((op, args))
            return [
                {"from": 0x1000, "to": 0x2000, "type": "CALL"},
                {"from": 0x2010, "to": 0x3000, "type": "CALL"},
                {"from": 0x4000, "to": 0x1000, "type": "DATA"},
            ]
        if op == "function_at":
            self.calls.append((op, args))
            ea = int(args["ea"])
            for start, name in self.FUNCTIONS:
                if start <= ea < start + self.SIZE:
                    return {
                        "addr": start,
                        "name": name,
                        "size": self.SIZE,
                        "end": start + self.SIZE - 1,
                    }
            raise NotFuncError(f"address 0x{ea:x} is not inside a function")
        return super().call(op, **args)


def test_axg_json_matches_r2_nested_shape():
    session, _ = make_session(XrefClient())
    payload = json.loads(session.run("axgj 0x3000")[0])
    root = payload["12288"]  # 0x3000, keyed like r2 as a decimal string
    assert root["type"] == "fcn"
    assert root["fcn_addr"] == 0x3000
    assert root["name"] == "fcn.leaf"
    # xrefs to 0x3000 come from the single call site 0x2010 inside fcn.helper.
    assert len(root["refs"]) == 1
    helper = root["refs"][0]["8208"]  # 0x2010
    assert helper["fcn_addr"] == 0x2000 and helper["name"] == "fcn.helper"
    # fcn.helper is reached from two call sites inside fcn.main, which itself
    # has no function-based callers (the DATA ref at 0x4000 is skipped).
    sites = [next(iter(entry)) for entry in helper["refs"]]
    assert sites == ["4112", "4120"]  # 0x1010, 0x1018
    for entry in helper["refs"]:
        ((_, node),) = entry.items()
        assert node["fcn_addr"] == 0x1000 and node["name"] == "fcn.main"
        assert node["refs"] == []


def test_axg_text_tree_and_star_commands():
    session, _ = make_session(XrefClient())
    assert session.run("axg 0x3000") == [
        "- 0x0000000000003000 fcn 0x0000000000003000 fcn.leaf",
        "  - 0x0000000000002010 fcn 0x0000000000002000 fcn.helper",
        "    - 0x0000000000001010 fcn 0x0000000000001000 fcn.main",
        "    - 0x0000000000001018 fcn 0x0000000000001000 fcn.main",
    ]
    assert session.run("axg* 0x3000") == [
        "'agn 0x0000000000003000 fcn.leaf",
        "'agn 0x0000000000002000 fcn.helper",
        "'agn 0x0000000000001000 fcn.main",
        "'agn 0x0000000000001000 fcn.main",
        "'age 0x0000000000002000 0x0000000000003000",
        "'age 0x0000000000001000 0x0000000000002000",
        "'age 0x0000000000001000 0x0000000000002000",
    ]


def test_axg_defaults_to_seek_and_handles_cycles_and_non_functions():
    session, _ = make_session(XrefClient())
    session.run("s 0x3000")
    assert json.loads(session.run("axgj")[0]) == json.loads(session.run("axgj 0x3000")[0])

    session.run("s 0x9000")
    assert session.run("axgj") == ["{}"]
    assert session.run("axg") == []

    # A function that is its own caller must not loop forever.
    session.seek = 0x1000

    class CycleClient(XrefClient):
        def call(self, op, **args):
            if op == "xrefs_to" and int(args["ea"]) == 0x1000:
                self.calls.append((op, args))
                return [{"from": 0x1010, "to": 0x1000, "type": "CALL"}]
            return super().call(op, **args)

    session.client = CycleClient()
    payload = json.loads(session.run("axgj")[0])
    assert payload["4096"]["name"] == "fcn.main"
    ((_, caller),) = payload["4096"]["refs"][0].items()
    assert caller["fcn_addr"] == 0x1000 and caller["refs"] == []


def test_axg_help_lists_graph_variants():
    session, _ = make_session(XrefClient())
    assert "axg: show the xref graph reaching the current function" in session.run("axg?")


def test_axf_lists_references_to_matching_flags():
    session, _ = make_session(XrefClient())
    # flag_store holds entry/main @ 0x1000 and helper @ 0x2000 (load_flags).
    assert session.run("axF helper") == [
        "0x0000000000001010 CALL -> 0x0000000000002000",
        "0x0000000000001018 CALL -> 0x0000000000002000",
    ]
    # Glob form matches every flag; entry/main share 0x1000 and must dedupe.
    assert session.run("axF *") == [
        "0x0000000000004000 DATA -> 0x0000000000001000",
        "0x0000000000001010 CALL -> 0x0000000000002000",
        "0x0000000000001018 CALL -> 0x0000000000002000",
    ]
    # Substring form mirrors r2's flag-name resolution.
    assert session.run("axF ent") == ["0x0000000000004000 DATA -> 0x0000000000001000"]
    assert session.run("axF zzz") == []


def test_axf_requires_a_pattern():
    session, _ = make_session(XrefClient())
    session.run("axF")
    assert session.failed
    assert "needs a flag glob" in str(session.last_error)


def test_ax_dot_lists_refs_from_and_to():
    session, _ = make_session(XrefClient())
    assert session.run("ax. 0x1000") == [
        "0x0000000000001000 CALL -> 0x0000000000002000",
        "0x0000000000004000 DATA -> 0x0000000000001000",
    ]


def test_axq_and_ax_axl_list_all_references():
    session, _ = make_session(XrefClient())
    assert session.run("axq") == [
        "0x0000000000001000 -> 0x0000000000002000  CALL",
        "0x0000000000002010 -> 0x0000000000003000  CALL",
        "0x0000000000004000 -> 0x0000000000001000  DATA",
    ]
    expected = [
        "entry 0x0000000000001000 > CALL > 0x0000000000002000 helper",
        "      0x0000000000002010 > CALL > 0x0000000000003000",
        "      0x0000000000004000 > DATA > 0x0000000000001000 entry",
    ]
    assert session.run("ax") == expected
    assert session.run("axl") == expected


def test_ax_with_args_reports_write_rejection():
    session, _ = make_session(XrefClient())
    session.run("ax 0x1000")
    assert session.failed
    assert "writes references" in str(session.last_error)


def test_axff_matches_afx_semantics():
    session, _ = make_session(XrefClient())
    assert session.run("axff") == ["0x0000000000001000 CALL -> 0x0000000000004000"]
    payload = json.loads(session.run("axffj")[0])
    assert payload[0]["from"] == 0x1000 and payload[0]["to"] == 0x4000


def test_axv_lists_variable_read_write_sections():
    session, _ = make_session(XrefClient())
    lines = session.run("axv @ main")
    assert lines == [
        "afvR",
        "   local_8  0x0000000000001000 0x0000000000001004",
        "afvW",
        "   local_8  0x0000000000001000 0x0000000000001004",
    ]


def test_axv_is_silent_outside_a_function():
    class NoVarsClient(XrefClient):
        def call(self, op, **args):
            if op == "variable_refs":
                self.calls.append((op, args))
                raise NotFuncError("address 0x9000 is not inside a function")
            return super().call(op, **args)

    session, _ = make_session(NoVarsClient())
    assert session.run("axv 0x9000") == []


def test_write_ref_variants_are_explicitly_unsupported():
    session, _ = make_session(XrefClient())
    for line in ("axc 0x1000", "axC 0x1000", "axd 0x1000", "axi 0x1000", "axm 0x1000",
                 "axr 0x1000", "axs 0x1000", "axw 0x1000", "ax-", "ax-*"):
        session.failed = False
        session.last_error = None
        session.run(line)
        assert session.failed, line
        assert "writes references" in str(session.last_error), line


def test_axh_is_not_a_radare2_6x_command():
    session, _ = make_session(XrefClient())
    session.run("axH")
    assert session.failed
    assert "not a radare2 6.x command" in str(session.last_error)


def test_axj_stays_unsupported():
    session, _ = make_session(XrefClient())
    session.run("axj 0x1000")
    assert session.failed
    assert "read-only for xrefs" in str(session.last_error)
