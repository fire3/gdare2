"""Tests for the ag graph family: DOT output, agC commands and unsupported variants."""

from __future__ import annotations

import json

import pytest
from test_session import FakeClient, make_session

from gdare2.errors import UnsupportedError
from gdare2.fmt.graph import format_dot_callgraph
from gdare2.parser import parse_statement

CALL_GRAPH = {
    "root": 0x1000,
    "depth": 1,
    "nodes": [
        {"addr": 0x1000, "name": "main", "size": 10},
        {"addr": 0x2000, "name": "helper", "size": 20},
        {"addr": 0x3000, "name": "libc_start_main", "size": 0, "external": True},
    ],
    "edges": [
        {"src": 0x1000, "dst": 0x2000},
        {"src": 0x1000, "dst": 0x3000},
        {"src": 0x2000, "dst": 0x1000},
    ],
    "truncated": False,
}

ROOT_ONLY = {
    "root": 0x1000,
    "depth": 0,
    "nodes": [{"addr": 0x1000, "name": "main", "size": 10}],
    "edges": [],
    "truncated": False,
}


class CallGraphClient(FakeClient):
    def call(self, op, **args):
        if op == "call_graph":
            self.calls.append((op, args))
            depth = int(args.get("depth", 1))
            if depth <= 0:
                return json.loads(json.dumps(ROOT_ONLY))
            payload = json.loads(json.dumps(CALL_GRAPH))
            payload["depth"] = depth
            return payload
        return super().call(op, **args)


def test_dot_callgraph_renders_nodes_and_edges():
    lines = format_dot_callgraph(CALL_GRAPH)
    assert lines[0] == "digraph callgraph {"
    assert '  node [shape=box, fontname="monospace"];' in lines
    assert '  "0x1000" [label="main"];' in lines
    assert '  "0x2000" [label="helper"];' in lines
    assert '  "0x3000" [label="libc_start_main", style=dashed];' in lines
    assert '  "0x1000" -> "0x2000";' in lines
    assert '  "0x2000" -> "0x1000";' in lines
    assert lines[-1] == "}"


def test_dot_callgraph_sorts_nodes_and_escapes_labels():
    payload = {
        "nodes": [
            {"addr": 0x2000, "name": 'sec"ond'},
            {"addr": 0x1000, "name": "first"},
        ],
        "edges": [{"src": 0x2000, "dst": 0x1000}],
    }
    lines = format_dot_callgraph(payload)
    node_lines = [line for line in lines if "label=" in line]
    assert node_lines[0].startswith('  "0x1000"')
    assert node_lines[1].startswith('  "0x2000"')
    assert 'label="sec\\"ond"' in node_lines[1]


def test_dot_callgraph_handles_empty_payload():
    lines = format_dot_callgraph({})
    assert lines[0] == "digraph callgraph {"
    assert lines[-1] == "}"
    assert len(lines) == 4


def test_agc_json_and_depth_argument():
    session, client = make_session(CallGraphClient())
    payload = json.loads("\n".join(session.run("agCj")))
    assert payload["root"] == 0x1000
    assert payload["depth"] == 1
    assert len(payload["nodes"]) == 3
    session.run("agC 2")
    assert ("call_graph", {"allow_writes": False, "ea": 0x1000, "depth": 2}) in client.calls


def test_agc_text_lists_nodes_and_edges():
    session, _ = make_session(CallGraphClient())
    lines = session.run("agC")
    assert "0x0000000000001000 main" in lines
    assert "0x0000000000003000 libc_start_main (external)" in lines
    assert "main -> helper" in lines
    assert "main -> libc_start_main" in lines
    assert "helper -> main" in lines


def test_agc_zero_depth_keeps_the_root():
    session, _ = make_session(CallGraphClient())
    lines = session.run("agC 0")
    assert lines == ["0x0000000000001000 main"]


def test_agc_dot_matches_the_renderer():
    session, _ = make_session(CallGraphClient())
    assert session.run("agCd") == format_dot_callgraph(CALL_GRAPH)


def test_ag_renders_dot_of_the_current_function():
    session, _ = make_session()
    dot = "\n".join(session.run("ag"))
    assert dot.startswith('digraph "main"')
    assert '"0x1000" -> "0x1010"' in dot


def test_agc_rejects_bad_depth():
    session, _ = make_session(CallGraphClient())
    session.run("agC -1")
    assert session.failed and "depth" in str(session.last_error)
    session.failed = False
    session.run("agC nope")
    assert session.failed and "numeric" in str(session.last_error)


@pytest.mark.parametrize("cmd", ["agd", "agj", "ag*", "ag-", "agR", "agX"])
def test_unsupported_graph_variants(cmd):
    session, client = make_session()
    with pytest.raises(UnsupportedError):
        session.run_statement(parse_statement(cmd))
    assert client.calls == []
