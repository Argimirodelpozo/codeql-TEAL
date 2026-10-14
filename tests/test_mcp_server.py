"""The dependency-free MCP server (``tealql.agent.server``).

Pins the protocol surface a client depends on: the ``initialize`` handshake
(version negotiation, capabilities, instructions), ``tools/list`` mirroring the
registry, ``tools/call`` returning ``structuredContent`` + a text block, tool
errors as ``isError`` results (not protocol errors), and the JSON-RPC error
codes for malformed input. One subprocess smoke test proves stdout carries
only protocol messages.
"""
from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path

from tealql.agent import tools as T
from tealql.agent.server import McpServer, PROTOCOL_VERSIONS

TESTS = Path(__file__).resolve().parent
UNGUARDED = TESTS / "benchmark" / "tainted-fund-flow" / "vuln" / "unguarded_receiver.teal"


def _req(id_, method, params=None) -> str:
    msg = {"jsonrpc": "2.0", "id": id_, "method": method}
    if params is not None:
        msg["params"] = params
    return json.dumps(msg)


def _notif(method, params=None) -> str:
    msg = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    return json.dumps(msg)


def test_handshake_tools_list_and_call_through_the_in_memory_loop():
    lines = [
        _req(1, "initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                               "clientInfo": {"name": "t", "version": "0"}}),
        _notif("notifications/initialized"),
        _req(2, "tools/list"),
        _req(3, "tools/call", {"name": "tealql_verify_sinks",
                               "arguments": {"target": str(UNGUARDED)}}),
        _req(4, "ping"),
    ]
    out = io.StringIO()
    srv = McpServer(reader=io.StringIO("\n".join(lines) + "\n"), writer=out)
    assert srv.serve() == 0
    responses = [json.loads(ln) for ln in out.getvalue().splitlines()]
    assert [r["id"] for r in responses] == [1, 2, 3, 4]          # the notification got no reply
    init = responses[0]["result"]
    assert init["protocolVersion"] == "2024-11-05"               # echoed: supported
    assert init["capabilities"] == {"tools": {"listChanged": False},
                                    "prompts": {"listChanged": False}}
    assert init["serverInfo"]["name"] == "tealql" and "OVER-approximates" in init["instructions"]
    assert srv.initialized is True
    tools = responses[1]["result"]["tools"]
    assert [t["name"] for t in tools] == list(T.TOOLS)
    assert all({"name", "description", "inputSchema", "annotations"} <= set(t) for t in tools)
    call = responses[2]["result"]
    assert call["isError"] is False
    assert call["structuredContent"]["counts"] == {"CONFIRMED": 1}
    assert call["content"][0]["type"] == "text"
    assert json.loads(call["content"][0]["text"]) == call["structuredContent"]
    assert responses[3]["result"] == {}


def test_version_negotiation_falls_back_to_newest_supported():
    srv = McpServer(reader=io.StringIO(), writer=io.StringIO())
    r = srv.handle_line(_req(1, "initialize", {"protocolVersion": "1999-01-01"}))
    assert r["result"]["protocolVersion"] == PROTOCOL_VERSIONS[0]
    r = srv.handle_line(_req(2, "initialize", {}))
    assert r["result"]["protocolVersion"] == PROTOCOL_VERSIONS[0]


def test_error_taxonomy_tool_errors_are_results_protocol_errors_are_errors():
    srv = McpServer(reader=io.StringIO(), writer=io.StringIO())
    # Malformed tool arguments: the TOOL's error, delivered as a result the model can read.
    r = srv.handle_line(_req(1, "tools/call", {"name": "tealql_analyze", "arguments": {"bogus": 1}}))
    assert r["result"]["isError"] is True and "unknown argument" in r["result"]["content"][0]["text"]
    r = srv.handle_line(_req(2, "tools/call", {"name": "tealql_analyze",
                                               "arguments": {"target": "/no/such.teal"}}))
    assert r["result"]["isError"] is True and "does not exist" in r["result"]["content"][0]["text"]
    # Unknown tool / bad params shape: protocol-level invalid params.
    r = srv.handle_line(_req(3, "tools/call", {"name": "tealql_nope", "arguments": {}}))
    assert r["error"]["code"] == -32602 and "unknown tool" in r["error"]["message"]
    r = srv.handle_line(_req(4, "tools/call", {"name": "tealql_analyze", "arguments": []}))
    assert r["error"]["code"] == -32602
    r = srv.handle_line(_req(5, "tools/call", "nope"))
    assert r["error"]["code"] == -32602
    # Method / request / parse errors.
    r = srv.handle_line(_req(6, "no/such"))
    assert r["error"]["code"] == -32601
    r = srv.handle_line("{not json")
    assert r["error"]["code"] == -32700 and r["id"] is None
    r = srv.handle_line("[1, 2]")
    assert r["error"]["code"] == -32600
    r = srv.handle_line(json.dumps({"id": 7, "method": "ping"}))        # no jsonrpc tag
    assert r["error"]["code"] == -32600
    # Notifications never get a reply, even unknown ones; neither do responses.
    assert srv.handle_line(_notif("notifications/cancelled", {"requestId": 1})) is None
    assert srv.handle_line(_notif("something/odd")) is None
    assert srv.handle_line(json.dumps({"jsonrpc": "2.0", "id": 9, "result": {}})) is None
    assert srv.handle_line("") is None
    # Optional capability listings answer empty rather than erroring.
    assert srv.handle_line(_req(8, "resources/list"))["result"] == {"resources": []}


def test_triage_prompt_list_get_and_record_tool_annotations():
    srv = McpServer(reader=io.StringIO(), writer=io.StringIO())
    listed = srv.handle_line(_req(1, "prompts/list"))["result"]["prompts"]
    assert [p["name"] for p in listed] == ["triage_findings"]
    assert listed[0]["arguments"] == [{"name": "target", "required": True,
                                       "description": listed[0]["arguments"][0]["description"]}]
    got = srv.handle_line(_req(2, "prompts/get", {"name": "triage_findings",
                                                  "arguments": {"target": "app.teal"}}))["result"]
    (msg,) = got["messages"]
    assert msg["role"] == "user" and msg["content"]["type"] == "text"
    text = msg["content"]["text"]
    for needle in ('target="app.teal"', "tealql_triage_queue", "tealql_record_triage",
                   "tealql_decompile", "NEVER mark false_positive without citing"):
        assert needle in text, needle
    # Spec errors: unknown prompt / missing required argument -> invalid params.
    assert srv.handle_line(_req(3, "prompts/get", {"name": "nope"}))["error"]["code"] == -32602
    assert srv.handle_line(_req(4, "prompts/get",
                                {"name": "triage_findings"}))["error"]["code"] == -32602
    # Only the record tool writes, and its write is additive (not destructive).
    ann = {t["name"]: t["annotations"]
           for t in srv.handle_line(_req(5, "tools/list"))["result"]["tools"]}
    assert ann["tealql_record_triage"]["readOnlyHint"] is False
    assert ann["tealql_record_triage"]["destructiveHint"] is False
    assert [n for n, a in ann.items() if not a["readOnlyHint"]] == ["tealql_record_triage"]
    assert ann["tealql_triage_queue"]["readOnlyHint"] is True


def test_a_crashing_tool_is_reported_as_the_tools_error_not_a_dead_session():
    def boom(**_):
        raise RuntimeError("kaboom")
    fake = {"t_boom": T.Tool("t_boom", "boom", {"type": "object", "properties": {},
                                                "required": [], "additionalProperties": False}, boom)}
    srv = McpServer(tools=fake, reader=io.StringIO(), writer=io.StringIO())
    r = srv.handle_line(_req(1, "tools/call", {"name": "t_boom", "arguments": {}}))
    assert r["result"]["isError"] is True and "RuntimeError: kaboom" in r["result"]["content"][0]["text"]
    assert srv.handle_line(_req(2, "ping"))["result"] == {}      # session still alive


def test_stdio_subprocess_emits_only_protocol_messages():
    stdin = "\n".join([
        _req(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                               "clientInfo": {"name": "t", "version": "0"}}),
        _notif("notifications/initialized"),
        _req(2, "tools/list"),
        _req(3, "tools/call", {"name": "tealql_analyze",
                               "arguments": {"teal": "#pragma version 8\nint 1\nreturn\n",
                                             "mode": "app"}}),
    ]) + "\n"
    proc = subprocess.run([sys.executable, "-m", "tealql.agent.server"], input=stdin,
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    lines = proc.stdout.splitlines()
    assert len(lines) == 3, proc.stdout                          # every line parses as JSON-RPC
    msgs = [json.loads(ln) for ln in lines]
    assert [m["id"] for m in msgs] == [1, 2, 3]
    assert msgs[2]["result"]["isError"] is False
    assert msgs[2]["result"]["structuredContent"]["complete"] is True
