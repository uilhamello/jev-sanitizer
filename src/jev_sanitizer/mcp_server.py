"""MCP server (stdio, JSON-RPC, stdlib only). Tools: jev_ask, jev_dry_run, jev_models."""
from __future__ import annotations

import json
import sys

from . import __version__
from .client import JevClient

QUESTION = {
    "type": "object",
    "properties": {
        "type": {"enum": ["noul", "choice", "score"]},
        "instructions": {"type": "string"},
        "criteria": {"description": "noul: {true, false} | choice: {option_snake_case: description} | score: [level0, level1, ...]"},
    },
    "required": ["type", "instructions", "criteria"],
}
ASK = {
    "type": "object",
    "properties": {
        "state": {"type": "string", "description": "Context to judge. Only what is needed, already summarized."},
        "questions": {"type": "object", "additionalProperties": QUESTION, "description": "1-20 questions {name_snake_case: question}"},
        "model": {"type": "string"},
        "origin": {"type": "string", "description": "Caller id (e.g. my-skill:triage), local log only"},
    },
    "required": ["state", "questions"],
}
TOOLS = {
    "jev_ask": ("Ask Jev (TypeSafe) typed decisions about a state: noul (yes/no probability), choice (one option), "
                "score (ordered level). Sanitizes PII/secrets first and blocks if anything risky remains. "
                "status 'unavailable' means no answer — never treat it as agreement.", ASK),
    "jev_dry_run": ("Show the sanitized request jev_ask would send, without sending it.", ASK),
    "jev_models": ("List Jev models available to the configured account.", {"type": "object", "properties": {}}),
}


class Server:
    def __init__(self, client: JevClient | None = None):
        self._client = client

    @property
    def client(self) -> JevClient:
        if self._client is None:  # lazy: config errors surface as tool errors, not a crash at startup
            self._client = JevClient()
        return self._client

    def call(self, name: str, args: dict) -> dict:
        if name == "jev_models":
            return self.client.models()
        fn = self.client.ask if name == "jev_ask" else self.client.dry_run
        kw = {"model": args.get("model")}
        if name == "jev_ask":
            kw["origin"] = args.get("origin", "mcp")
        return fn(args.get("state"), args.get("questions"), **kw)

    def handle(self, msg: dict) -> dict | None:
        method, mid = msg.get("method"), msg.get("id")
        if method == "initialize":
            res = {"protocolVersion": msg.get("params", {}).get("protocolVersion", "2025-06-18"),
                   "capabilities": {"tools": {}}, "serverInfo": {"name": "jev-sanitizer", "version": __version__}}
        elif method == "tools/list":
            res = {"tools": [{"name": n, "description": d, "inputSchema": s} for n, (d, s) in TOOLS.items()]}
        elif method == "tools/call":
            p = msg.get("params", {})
            if p.get("name") not in TOOLS:
                return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "unknown tool"}}
            try:
                out, is_error = self.call(p["name"], p.get("arguments") or {}), False
            except (ValueError, RuntimeError) as e:
                out, is_error = {"error": str(e)}, True
            except Exception as e:  # never leave a request without its answer
                out, is_error = {"error": type(e).__name__}, True
            res = {"content": [{"type": "text", "text": json.dumps(out, ensure_ascii=False, indent=1)}], "isError": is_error}
        elif method == "ping":
            res = {}
        elif mid is None:
            return None  # notifications
        else:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found"}}
        return {"jsonrpc": "2.0", "id": mid, "result": res}


def main() -> None:
    server = Server()
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
        except ValueError as e:
            resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": type(e).__name__}}
        else:
            try:
                resp = server.handle(msg)
            except Exception as e:  # keep the id so the caller is not left waiting
                mid = msg.get("id") if isinstance(msg, dict) else None
                resp = {"jsonrpc": "2.0", "id": mid, "error": {"code": -32603, "message": type(e).__name__}}
        if resp is not None:
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
