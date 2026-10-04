"""Jev client: validates typed questions, sanitizes everything that leaves, calls the API.

Result `status`:
  ok          -> `answers` holds the typed answers
  blocked     -> sanitizer found PII/secret it could not mask; nothing was sent
  unavailable -> network, key or API failure; callers must NOT treat it as an answer
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from .config import Config, load_config
from text_sanitizer_core import Report

NAME = re.compile(r"^[a-z][a-z0-9_]{0,40}$")
MODEL = re.compile(r"^[a-z0-9][a-z0-9./-]{1,60}$")
MAX_QUESTIONS = 20


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """urllib re-sends Authorization to wherever a redirect points (any host, even plain http)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # the 3xx surfaces as HTTPError -> status "unavailable"


_OPENER = urllib.request.build_opener(_NoRedirect)


class JevClient:
    def __init__(self, config: Config | None = None, **overrides):
        self.config = config or load_config(**overrides)
        self.sanitizer = self.config.build_sanitizer()

    # ---- validation + sanitization -------------------------------------------------------------
    def _clean(self, text, where: str, report: Report) -> str:
        if not self.config.sanitize:
            return str(text)
        clean, r = self.sanitizer.sanitize(str(text))
        report.merge(r, where)
        return clean

    def _ident(self, value, where: str, report: Report) -> None:
        """Identifiers (model, question names, option keys) are sent verbatim: block if they carry PII."""
        if self.config.sanitize and self.sanitizer.sanitize(str(value))[0] != str(value):
            report.blocked.append(f"{where}:pii_in_identifier")

    def _question(self, name, q, report: Report) -> dict:
        if not NAME.match(str(name)):
            raise ValueError(f"question {name!r}: use snake_case")
        if not isinstance(q, dict) or q.get("type") not in ("noul", "choice", "score"):
            raise ValueError(f"question {name}: type must be noul, choice or score")
        if not isinstance(q.get("instructions"), str) or not q["instructions"].strip():
            raise ValueError(f"question {name}: instructions required")
        self._ident(name, f"name:{name}", report)
        kind, crit = q["type"], q.get("criteria")
        out = {"type": kind, "instructions": self._clean(q["instructions"], name, report)}
        if kind == "noul":
            if not isinstance(crit, dict) or set(crit) != {"true", "false"}:
                raise ValueError(f"question {name}: noul needs criteria {{true, false}}")
            out["criteria"] = {k: self._clean(v, name, report) for k, v in crit.items()}
        elif kind == "choice":
            if not isinstance(crit, dict) or not 2 <= len(crit) <= 20 or not all(NAME.match(str(k)) for k in crit):
                raise ValueError(f"question {name}: choice needs 2-20 snake_case options")
            for k in crit:
                self._ident(k, f"{name}.option", report)
            out["criteria"] = {k: self._clean(v, name, report) for k, v in crit.items()}
        else:
            if not isinstance(crit, list) or not 2 <= len(crit) <= 10:
                raise ValueError(f"question {name}: score needs a list of 2-10 ordered levels")
            out["criteria"] = [self._clean(v, name, report) for v in crit]
        return out

    def prepare(self, state, questions, model: str | None = None) -> tuple[dict, Report]:
        """Build the request body exactly as it would be sent. Raises ValueError on bad input."""
        if not isinstance(state, str) or not state.strip():
            raise ValueError("state: non-empty text required")
        if not isinstance(questions, dict) or not 1 <= len(questions) <= MAX_QUESTIONS:
            raise ValueError(f"questions: object with 1-{MAX_QUESTIONS} questions")
        model = model or self.config.model_name
        if not MODEL.match(model):
            raise ValueError("model: invalid name")
        report = Report()
        self._ident(model, "model", report)
        body = {"model": model, "state": self._clean(state, "state", report),
                "questions": {n: self._question(n, q, report) for n, q in questions.items()}}
        return body, report

    # ---- public API ------------------------------------------------------------------------------
    def dry_run(self, state, questions, model=None) -> dict:
        body, report = self.prepare(state, questions, model)
        return {"can_send": report.ok, "sanitized": self.config.sanitize, "masks": report.masks,
                "blocked": report.blocked, "would_send": body}

    def ask(self, state, questions, model=None, origin: str = "unknown") -> dict:
        body, report = self.prepare(state, questions, model)
        raw = json.dumps(body, ensure_ascii=False).encode()
        base = {"origin": str(origin)[:60], "sha256": hashlib.sha256(raw).hexdigest()[:16], "bytes": len(raw),
                "questions": len(body["questions"]), "sanitized": self.config.sanitize, "masks": report.masks}
        if not report.ok:
            self._log({**base, "status": "blocked", "reasons": report.blocked})
            return {"status": "blocked", "reasons": report.blocked, "masks": report.masks}
        t0 = time.time()
        try:
            resp = self._http("POST", self.config.endpoint["ask_path"], raw)
            out = {"status": "ok", "model": resp.get("model"), "answers": resp["answers"], "usage": resp.get("usage"),
                   "latency_s": round(time.time() - t0, 2), "sha256": base["sha256"], "masks": report.masks}
            self._log({**base, "status": "ok", "model": out["model"], "usage": out["usage"]})
            return out
        except Exception as e:  # never raise to the caller: unavailable is an explicit state
            reason = _reason(e)
        self._log({**base, "status": "unavailable", "reason": reason})
        return {"status": "unavailable", "reason": reason}

    def models(self) -> dict:
        try:
            return {"status": "ok", "models": [m.get("name") for m in self._http("GET", "/models").get("models", [])]}
        except Exception as e:
            return {"status": "unavailable", "reason": _reason(e)}

    # ---- internals -------------------------------------------------------------------------------
    def _http(self, method: str, path: str, body: bytes | None = None) -> dict:
        req = urllib.request.Request(self.config.endpoint["base_url"] + path, data=body, method=method,
                                     headers={"Authorization": "Bearer " + self.config.api_key(),
                                              "Content-Type": "application/json", "User-Agent": "jev-sanitizer"})
        with _OPENER.open(req, timeout=self.config.timeout) as r:
            return json.load(r)

    def _log(self, event: dict) -> None:
        """Local log WITHOUT content: origin, hash, size, masks, outcome."""
        if not self.config.log_path:
            return
        event["ts"] = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
        try:  # best effort: a broken log must never discard an answer or break the request
            path = Path(self.config.log_path).expanduser()
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, "a") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
        except OSError as e:
            print(f"jev-sanitizer: log disabled ({type(e).__name__})", file=sys.stderr)


def _reason(e: Exception) -> str:
    """Failure message that never leaks the response body or the key."""
    if isinstance(e, urllib.error.HTTPError):
        return f"HTTP {e.code}"
    if isinstance(e, RuntimeError):
        return str(e)
    return type(e).__name__
