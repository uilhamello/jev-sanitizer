"""Mask PII and secrets; block when something risky survives masking.

Fail secure: when in doubt, block. Only the text returned here may leave the machine.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

_SECRET_WORDS = r"pass(?:word)?|senha|pwd|token|secret|segredo|api[_-]?key|apikey|auth(?:orization)?|cookie|session(?:_?id)?|sid"

# Tokens with a well-known prefix: masked even when they would not trip the entropy check.
_KNOWN_TOKENS = (r"xox[abposr]-[A-Za-z0-9-]{10,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
                 r"|sk-(?:ant-)?[A-Za-z0-9_-]{20,}|[sr]k_(?:live|test)_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{35}")


def _luhn(digits: str) -> bool:
    total = 0
    for i, d in enumerate(reversed(digits)):
        n = int(d) * (2 if i % 2 else 1)
        total += n - 9 if n > 9 else n
    return total % 10 == 0


def _card(m: re.Match) -> str:
    """Payment card (13-19 digits, spaces or dashes allowed): masked only when the Luhn check passes."""
    digits = re.sub(r"\D", "", m.group(0))
    return "<CARD>" if 13 <= len(digits) <= 19 and _luhn(digits) else m.group(0)


# Order matters: specific patterns before generic ones (e.g. JWT before long hex).
# The replacement may be a callable (see _card), as accepted by re.sub.
DEFAULT_MASKS: list[tuple] = [
    ("private_key", r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", "<PRIVATE_KEY>"),
    ("jwt", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", "<JWT>"),
    ("bearer", r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}", "Bearer <TOKEN>"),
    ("known_token", r"\b(?:" + _KNOWN_TOKENS + r")", "<TOKEN>"),
    # Before cpf/cnpj/phone/long_number, which would otherwise take pieces of the number.
    ("card", r"(?<![\d.])\d(?:[ -]?\d){12,18}(?![\d.])", _card),
    # URL userinfo (scheme://user:pass@host) before anything else sees the "@".
    ("url_userinfo", r"(?i)\b([a-z][a-z0-9+.-]*://)[^\s/?#@]+@", r"\1<USERINFO>@"),
    # key=value, key: value, and quoted keys as in JSON ("password": "x").
    ("secret_kv", r"(?i)\b(?P<k>" + _SECRET_WORDS + r")\b(?P<sep>[\"']?\s*[=:]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;&}]+)",
     r"\g<k>\g<sep><SECRET>"),
    # Free text ("a senha é hunter2"): skip up to 3 short words, mask the first token with a digit.
    ("secret_word", r"(?i)\b(?P<k>" + _SECRET_WORDS + r")\b(?P<f>(?:\s+[^\W\d_]{1,7}){0,3}?)\s+(?=[^\s,;&]*\d)[^\s,;&]{4,}",
     r"\g<k>\g<f> <SECRET>"),
    ("url_query", r"(https?://[^\s?#]+)\?[^\s#]*", r"\1?<QUERY>"),
    ("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "<EMAIL>"),
    ("cnpj", r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b", "<CNPJ>"),
    ("cpf", r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b", "<CPF>"),
    ("phone_br", r"(?<!\d)(\+?55\s?)?\(?\d{2}\)?\s?9?\d{4}[-\s]\d{4}(?!\d)", "<PHONE>"),
    ("plate_br", r"(?i)\b[A-Z]{3}-?\d[A-Z0-9]\d{2}\b", "<PLATE>"),
    ("uuid", r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", "<UUID>"),
    ("ipv4", r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<IP>"),
    ("ipv6", r"\b(?:[0-9a-fA-F]{1,4}:){4,7}[0-9a-fA-F]{1,4}\b", "<IP>"),
    ("long_hex", r"\b[0-9a-fA-F]{32,}\b", "<HEX>"),
    # 6+ digit number without separators: treated as an identifier (raw CPF, card, account id).
    ("long_number", r"(?<![\d.,])\d{6,}(?![\d.,])", "<N>"),
    ("id_kv", r"(?i)\b(id(_[a-z]+)?|[a-z]+_id)\s*[=:]\s*\d+", r"\1=<N>"),
]

# Detectors that BLOCK even after masking (cannot be masked safely).
DEFAULT_BLOCKS: list[tuple[str, str]] = [
    ("aws_key", r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
    ("gcp_key", r"(?i)\"?private_key(_id)?\"?\s*:"),
    ("pem_header", r"-----BEGIN [A-Z ]*(PRIVATE KEY|CERTIFICATE)-----"),
    ("residual_at", r"[^\s>]@\S+\.\S"),  # ">@" is a mask placeholder (<USERINFO>@host)
    ("conn_string", r"(?i)\b(mysql|postgres(ql)?|mongodb(\+srv)?|redis|amqp|mssql|jdbc:[a-z]+)://"),
]

_SUSPECT_TOKEN = re.compile(r"[A-Za-z0-9+/_=-]{24,}")


@dataclass
class Report:
    masks: dict[str, int] = field(default_factory=dict)
    blocked: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.blocked

    def merge(self, other: "Report", where: str = "") -> None:
        for name, count in other.masks.items():
            self.masks[name] = self.masks.get(name, 0) + count
        self.blocked += [f"{where}:{b}" if where else b for b in other.blocked]


def _entropy(s: str) -> float:
    return -sum(s.count(c) / len(s) * math.log2(s.count(c) / len(s)) for c in set(s))


class Sanitizer:
    """Configurable sanitizer. Extra patterns come from config; defaults cannot be removed."""

    def __init__(self, extra_masks=(), extra_blocks=(), max_chars: int = 20000, entropy_threshold: float = 4.0):
        self.masks = [(n, re.compile(p), r) for n, p, r in [*DEFAULT_MASKS, *extra_masks]]
        self.blocks = [(n, re.compile(p)) for n, p in [*DEFAULT_BLOCKS, *extra_blocks]]
        self.max_chars = max_chars
        self.entropy_threshold = entropy_threshold

    def _high_entropy(self, text: str) -> bool:
        for m in _SUSPECT_TOKEN.finditer(text):
            t = m.group(0)
            classes = sum(bool(re.search(p, t)) for p in (r"[a-z]", r"[A-Z]", r"\d"))
            if classes >= 3 and _entropy(t) >= self.entropy_threshold:
                return True
        return False

    def sanitize(self, text) -> tuple[str, Report]:
        report = Report()
        if not isinstance(text, str):
            report.blocked.append("not_text")
            return "", report
        # Size first: the regexes are not linear on adversarial input, so oversized text never reaches them.
        if len(text) > self.max_chars:
            report.blocked.append(f"too_long>{self.max_chars}")
            return "", report
        clean = text
        for name, rx, repl in self.masks:
            clean, n = rx.subn(repl, clean)
            if n:
                report.masks[name] = report.masks.get(name, 0) + n
        report.blocked += [name for name, rx in self.blocks if rx.search(clean)]
        if self._high_entropy(clean):
            report.blocked.append("high_entropy")
        if len(clean) > self.max_chars:
            report.blocked.append(f"too_long>{self.max_chars}")
        return clean, report


_default = Sanitizer()


def sanitize(text) -> tuple[str, Report]:
    """Sanitize with the default rules."""
    return _default.sanitize(text)
