"""A dependency-free Model Context Protocol (MCP) server over stdio.

Speaks JSON-RPC 2.0, one message per line (the MCP stdio transport), and
publishes :data:`tealql.agent.tools.TOOLS`. Implemented directly rather than
through an SDK because the protocol surface a tool server needs is small
(``initialize``, ``tools/list``, ``tools/call``, ``prompts/list``,
``prompts/get``, ``ping``) and the project
keeps its runtime dependency list short on purpose.

Conventions that matter to a client:

* stdout carries ONLY protocol messages; everything else (logging, the puya
  backend's chatter) goes to stderr. ``initialize`` returns ``instructions``
  that teach the model the one thing it must know about a SAST tool: which
  results are verdicts and which are over-approximations.
* A tool that cannot honour a call (bad arguments, unusable target) returns a
  tool result with ``isError: true`` — the model can read the message and
  retry. Only protocol-level problems (unknown method, malformed JSON) become
  JSON-RPC errors.
* Every tool result carries the JSON payload twice: as ``structuredContent``
  (for clients that consume it) and pretty-printed in a ``text`` content block
  (for clients that only show text).

Run: ``tealql mcp`` or ``python -m tealql.agent.server``. Register in a client,
e.g. Claude Code ``.mcp.json``:
``{"mcpServers": {"tealql": {"command": "tealql", "args": ["mcp"]}}}``.
"""
from __future__ import annotations

import json
import logging
import sys
from typing import Any, Optional, TextIO

from .tools import TOOLS, ToolError

logger = logging.getLogger("tealql.agent.mcp")

#: Newest first. A client asking for one of these gets it echoed back; any other
#: request is answered with the newest (the spec's negotiation rule).
PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")

PARSE_ERROR, INVALID_REQUEST, METHOD_NOT_FOUND, INVALID_PARAMS, INTERNAL_ERROR = (
    -32700, -32600, -32601, -32602, -32603)

INSTRUCTIONS = """\
tealql analyses Algorand TEAL smart contracts (the AVM's native language) by
reconstructing SSA from the raw .teal — no high-level source needed — and
lifting it to a typed IR. Tools take `target` (a .teal file or a directory of
them) or `teal` (inline source).

How to read results:
- tealql_analyze and tealql_verify_sinks return VERDICTS: a finding means
  attacker-controlled data reaches a dangerous sink (or a privileged action is
  reachable) and no recognised guard dominates it. Still read the flagged code:
  detectors can be wrong in both directions.
- tealql_taint_query is reachability only. It OVER-approximates — a reachable
  sink may be perfectly validated — so use it to explore, never to conclude.
- `complete: false` with `notifications` means part of the analysis did not
  run (parse gap, unknown opcode, lift failure). Absence of findings there is
  not evidence of safety; say so in your report.
- NOT_FLAGGED is "a covering detector found nothing", not "proved guarded".

Mental model: the attacker controls this call's ApplicationArgs/accounts/
foreign arrays, every sibling transaction in the atomic group, and the sender.
A bug is attacker input reaching an inner-txn Receiver/Amount/CloseRemainderTo/
RekeyTo/Fee/ApplicationID, a state-write KEY, or a lifecycle action, without a
dominating check (sender == creator, receiver pinned to the app, etc.).

Suggested flow: tealql_brief (overview) → tealql_verify_sinks (CONFIRMED first)
→ tealql_source_context on each flagged line → tealql_decompile for the readable
IR when the TEAL is hard to follow.
"""


#: MCP prompts (``prompts/list`` / ``prompts/get``). Each: description, the
#: arguments, and a template rendered with them.
PROMPTS: dict[str, dict] = {
    "triage_findings": {
        "title": "Triage tealql findings",
        "description": ("Work the triage queue for a TEAL target: read each untriaged "
                        "finding's context, decide true_positive / false_positive / "
                        "needs_context, and record the verdict with its rationale."),
        "arguments": [{"name": "target", "required": True,
                       "description": "A .teal file or a directory of .teal files."}],
        "template": """\
Triage the tealql security findings for `{target}`.

Loop until the queue is empty or you run out of useful work:
1. Call tealql_triage_queue with target="{target}". Work the items in order
   (highest severity/confidence first). Each item carries its `fingerprint`,
   the finding (rule, message, line, witness) and a pre-joined
   `source_context` (source window, dominating path predicates, attacker
   inputs reaching the line, sinks reachable from it).
2. Read the context. When the TEAL is hard to follow call tealql_decompile
   (repr.pre_ir) and, for a different line, tealql_source_context.
3. Decide:
   - true_positive: attacker-controlled data (ApplicationArgs, accounts,
     foreign arrays, sibling group txns, sender) reaches the flagged sink or
     action with no dominating check that defeats the attack.
   - false_positive: a check the detector missed DOES dominate the sink on
     every path (e.g. sender == creator, receiver pinned, field asserted).
     NEVER mark false_positive without citing the guarding TEAL lines in
     `evidence_lines` and explaining in `rationale` why they hold on every
     path to the flagged line. The tool refuses a false_positive without them.
   - needs_context: the verdict depends on something outside the program
     (another contract, deployment parameters, an off-chain invariant). Say
     exactly what is missing.
4. Call tealql_record_triage with target="{target}", the item's
   `fingerprint`, `verdict`, `rationale`, `evidence_lines` and `reviewer`
   set to your model name.

Your verdicts are ADVICE stored beside the findings; they never change a
detector verdict. Finish with tealql_triage_report and summarise: counts per
verdict, every true_positive with its exploit path, and any stale records.
If the queue reports `complete: false`, say which part was not analysed.
""",
    },
}


def _version() -> str:
    try:
        from importlib.metadata import version
        return version("tealql")
    except Exception:
        return "0.0.0"


class McpServer:
    """Stateless request handler plus a stdio loop."""

    def __init__(self, tools: Optional[dict] = None, *, reader: Optional[TextIO] = None,
                 writer: Optional[TextIO] = None):
        self.tools = TOOLS if tools is None else tools
        self.reader = reader if reader is not None else sys.stdin
        self.writer = writer if writer is not None else sys.stdout
        self.initialized = False
        self.client_info: Optional[dict] = None

    # -- JSON-RPC plumbing ----------------------------------------------

    @staticmethod
    def _ok(msg_id, result) -> dict:
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    @staticmethod
    def _err(msg_id, code: int, message: str, data: Any = None) -> dict:
        err: dict = {"code": code, "message": message}
        if data is not None:
            err["data"] = data
        return {"jsonrpc": "2.0", "id": msg_id, "error": err}

    def handle_line(self, line: str) -> Optional[dict]:
        """One raw input line -> one response dict, or ``None`` (notification)."""
        line = line.strip()
        if not line:
            return None
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as e:
            return self._err(None, PARSE_ERROR, f"parse error: {e.msg}")
        if not isinstance(msg, dict):
            # JSON-RPC batches were removed in MCP 2025-06-18; refuse plainly.
            return self._err(None, INVALID_REQUEST, "expected a single JSON-RPC object")
        return self.handle_message(msg)

    def handle_message(self, msg: dict) -> Optional[dict]:
        msg_id = msg.get("id")
        method = msg.get("method")
        params = msg.get("params") or {}
        if msg.get("jsonrpc") != "2.0" or not isinstance(method, str):
            if method is None and ("result" in msg or "error" in msg):
                return None                     # a response to something we sent; we send nothing
            return self._err(msg_id, INVALID_REQUEST, "not a JSON-RPC 2.0 request")
        if not isinstance(params, dict):
            return self._err(msg_id, INVALID_PARAMS, "params must be an object")
        is_notification = "id" not in msg
        try:
            result = self._dispatch(method, params)
        except _MethodNotFound:
            if is_notification:
                return None                     # unknown notifications are ignored
            return self._err(msg_id, METHOD_NOT_FOUND, f"method not found: {method}")
        except _InvalidParams as e:
            return None if is_notification else self._err(msg_id, INVALID_PARAMS, str(e))
        except Exception as e:                  # a bug must not kill the session
            logger.exception("internal error handling %s", method)
            return None if is_notification else self._err(
                msg_id, INTERNAL_ERROR, f"{type(e).__name__}: {e}")
        if is_notification:
            return None
        return self._ok(msg_id, result)

    # -- MCP methods ----------------------------------------------------

    def _dispatch(self, method: str, params: dict):
        if method == "initialize":
            return self._initialize(params)
        if method == "notifications/initialized":
            self.initialized = True
            return None
        if method.startswith("notifications/"):
            return None
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": [t.mcp_descriptor() for t in self.tools.values()]}
        if method == "tools/call":
            return self._tools_call(params)
        if method in ("resources/list", "resources/templates/list"):
            return {"resources": []} if method == "resources/list" else {"resourceTemplates": []}
        if method == "prompts/list":
            return {"prompts": [
                {"name": name, "title": p["title"], "description": p["description"],
                 "arguments": p["arguments"]} for name, p in PROMPTS.items()]}
        if method == "prompts/get":
            return self._prompts_get(params)
        if method == "logging/setLevel":
            return {}
        raise _MethodNotFound(method)

    def _initialize(self, params: dict) -> dict:
        asked = params.get("protocolVersion")
        self.client_info = params.get("clientInfo")
        return {
            "protocolVersion": asked if asked in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0],
            "capabilities": {"tools": {"listChanged": False},
                             "prompts": {"listChanged": False}},
            "serverInfo": {"name": "tealql", "title": "TealQL — Algorand TEAL static analysis",
                           "version": _version()},
            "instructions": INSTRUCTIONS,
        }

    def _prompts_get(self, params: dict) -> dict:
        name = params.get("name")
        if not isinstance(name, str) or name not in PROMPTS:
            raise _InvalidParams(f"unknown prompt: {name!r}; available: {sorted(PROMPTS)}")
        args = params.get("arguments") or {}
        if not isinstance(args, dict):
            raise _InvalidParams("arguments must be an object")
        spec = PROMPTS[name]
        missing = [a["name"] for a in spec["arguments"]
                   if a.get("required") and not isinstance(args.get(a["name"]), str)]
        if missing:
            raise _InvalidParams(f"missing required argument(s) {missing}")
        text = spec["template"].format(**{a["name"]: args.get(a["name"], "")
                                          for a in spec["arguments"]})
        return {"description": spec["description"],
                "messages": [{"role": "user", "content": {"type": "text", "text": text}}]}

    def _tools_call(self, params: dict) -> dict:
        name = params.get("name")
        arguments = params.get("arguments")
        if arguments is None:
            arguments = {}
        if not isinstance(name, str) or name not in self.tools:
            raise _InvalidParams(f"unknown tool: {name!r}; available: {sorted(self.tools)}")
        if not isinstance(arguments, dict):
            raise _InvalidParams("arguments must be an object")
        tool = self.tools[name]
        try:
            payload = tool.call(arguments)
        except ToolError as e:
            return _tool_error(str(e))
        except Exception as e:
            # The tool crashed on a legitimate input: report it as the tool's
            # error so the model can reformulate, and log the traceback.
            logger.exception("tool %s crashed", name)
            return _tool_error(f"{type(e).__name__}: {e}")
        text = json.dumps(payload, indent=1, ensure_ascii=False, default=str)
        return {"content": [{"type": "text", "text": text}],
                "structuredContent": payload, "isError": False}

    # -- stdio loop -----------------------------------------------------

    def _send(self, response: dict) -> None:
        self.writer.write(json.dumps(response, ensure_ascii=False, default=str) + "\n")
        self.writer.flush()

    def serve(self) -> int:
        """Read requests until EOF. Returns the process exit code."""
        logger.info("tealql MCP server ready (%d tools)", len(self.tools))
        for line in self.reader:
            response = self.handle_line(line)
            if response is not None:
                self._send(response)
        return 0


class _MethodNotFound(Exception):
    pass


class _InvalidParams(Exception):
    pass


def _tool_error(message: str) -> dict:
    return {"content": [{"type": "text", "text": f"error: {message}"}], "isError": True}


def main(argv: Optional[list[str]] = None) -> int:
    """``python -m tealql.agent.server`` entry point."""
    import argparse
    p = argparse.ArgumentParser(prog="tealql-mcp",
                                description="TealQL MCP server over stdio.")
    p.add_argument("--list-tools", action="store_true",
                   help="print the tool names + descriptions and exit")
    p.add_argument("-v", "--verbose", action="count", default=0)
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose > 1 else
                        logging.INFO if args.verbose else logging.WARNING,
                        stream=sys.stderr, format="%(levelname)-7s %(message)s")
    if args.list_tools:
        for t in TOOLS.values():
            print(f"{t.name}\n    {t.description}\n")
        return 0
    return McpServer().serve()


if __name__ == "__main__":
    sys.exit(main())
