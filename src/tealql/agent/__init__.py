"""Agent-facing surface of TealQL: typed tools an LLM agent can call.

Three pieces, each importable on its own:

- :mod:`.tools` — the tool registry. Every tool is a plain Python function with
  a JSON-Schema input contract that returns one JSON-serialisable ``dict``
  carrying the project's standard completeness envelope (``complete`` +
  ``notifications``) wherever an analysis can be partial. Tools are the ONLY
  thing the MCP server exposes, so they are what gets tested.
- :mod:`.brief` — the *contract brief*: one call that turns a ``.teal`` program
  into the structured summary an auditor (human or model) wants first — ABI
  surface, lifecycle, storage, inner transactions, forced group shape, the
  attacker-reachable sinks with their verdicts, and the detector findings.
- :mod:`.server` — a dependency-free Model Context Protocol server over stdio
  (JSON-RPC 2.0, newline-delimited) that publishes the registry.

Dependency direction: ``agent -> security -> tealtools``. Nothing below this
package imports it.
"""
from __future__ import annotations

__all__ = ["TOOLS", "Tool", "ToolError", "call_tool", "contract_brief",
           "render_brief_markdown", "McpServer"]


def __getattr__(name: str):
    # Lazy so `import tealql.agent` stays cheap and import-order neutral.
    if name in ("TOOLS", "Tool", "ToolError", "call_tool"):
        from . import tools as _t
        return getattr(_t, name)
    if name in ("contract_brief", "render_brief_markdown"):
        from . import brief as _b
        return getattr(_b, name)
    if name == "McpServer":
        from .server import McpServer
        return McpServer
    raise AttributeError(name)
