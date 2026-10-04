"""Configuration: defaults < config file < environment variables.

Config file (TOML), first found:
  $JEV_SANITIZER_CONFIG, ~/.config/jev-sanitizer/config.toml
The current directory is never read: a cloned repo must not be able to turn sanitization off.
"""
from __future__ import annotations

import os
import stat
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

# Providers: fixed hosts only. No arbitrary base URL (prevents sending data/key to an unknown host).
PROVIDERS = {
    "typesafe": {"base_url": "https://api.typesafe.ai/v1", "ask_path": "/systemone", "key_env": "TYPESAFE_API_KEY",
                 "default_model": "jev-latest"},
    "vercel": {"base_url": "https://ai-gateway.vercel.sh/typesafe/v1", "ask_path": "/systemone", "key_env": "AI_GATEWAY_API_KEY",
               "default_model": "typesafe-ai/jev"},
}


@dataclass
class Config:
    provider: str = "typesafe"
    model: str | None = None
    key_file: str | None = None
    timeout: float = 15.0
    sanitize: bool = True
    ner: bool = False                                 # person names via spaCy (extra "ner")
    sanitizers: list = field(default_factory=lambda: ["br"])  # regions for text-sanitizer-core, e.g. ["br", "eu"]
    max_chars: int = 20000
    log_path: str | None = str(Path("~/.local/state/jev-sanitizer/requests.jsonl").expanduser())
    extra_masks: list = field(default_factory=list)   # [[name, regex, replacement], ...]
    extra_blocks: list = field(default_factory=list)  # [[name, regex], ...]

    @property
    def endpoint(self) -> dict:
        if self.provider not in PROVIDERS:
            raise ValueError(f"provider must be one of {sorted(PROVIDERS)}")
        return PROVIDERS[self.provider]

    @property
    def model_name(self) -> str:
        return self.model or self.endpoint["default_model"]

    def build_sanitizer(self):
        """One pass with the core rules plus each configured region; a missing region blocks every call."""
        from text_sanitizer_core import build

        return build(self.sanitizers, ner=self.ner, max_chars=self.max_chars,
                     extra_masks=self.extra_masks, extra_blocks=self.extra_blocks)

    def api_key(self) -> str:
        env = self.endpoint["key_env"]
        if os.environ.get(env):
            return os.environ[env]
        if self.key_file:
            return _read_key_file(Path(self.key_file).expanduser(), env)
        raise RuntimeError(f"missing API key: set {env} or key_file")


def _read_key_file(path: Path, env: str) -> str:
    try:
        mode = path.stat().st_mode
    except FileNotFoundError:
        raise RuntimeError(f"key_file not found: {path}")
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise RuntimeError(f"key_file must be chmod 600: {path}")
    for line in path.read_text().splitlines():
        line = line.strip().removeprefix("export ").strip()
        if line.startswith(env + "="):
            return line.split("=", 1)[1].strip().strip("'\"")
    raise RuntimeError(f"{env} not found in {path}")


def _config_file() -> Path | None:
    for p in (os.environ.get("JEV_SANITIZER_CONFIG"), "~/.config/jev-sanitizer/config.toml"):
        if p and Path(p).expanduser().is_file():
            return Path(p).expanduser()
    return None


def load_config(**overrides) -> Config:
    data: dict = {}
    path = _config_file()
    if path:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    env_map = {"JEV_SANITIZER_PROVIDER": "provider", "JEV_SANITIZER_MODEL": "model", "JEV_SANITIZER_KEY_FILE": "key_file",
               "JEV_SANITIZER_TIMEOUT": "timeout", "JEV_SANITIZER_LOG": "log_path", "JEV_SANITIZER_SANITIZE": "sanitize",
               "JEV_SANITIZER_NER": "ner", "JEV_SANITIZER_SANITIZERS": "sanitizers"}
    for env, key in env_map.items():
        if env in os.environ:
            data[key] = os.environ[env]
    data.update({k: v for k, v in overrides.items() if v is not None})
    known = set(Config.__dataclass_fields__)
    unknown = set(data) - known
    if unknown:
        raise ValueError(f"unknown config keys: {sorted(unknown)}")
    if isinstance(data.get("sanitize"), str):
        data["sanitize"] = data["sanitize"].strip().lower() not in ("0", "false", "no", "off")
    if isinstance(data.get("sanitizers"), str):  # env: "br,eu"
        data["sanitizers"] = [n.strip() for n in data["sanitizers"].split(",") if n.strip()]
    if isinstance(data.get("ner"), str):
        data["ner"] = data["ner"].strip().lower() in ("1", "true", "yes", "on")
    if "timeout" in data:
        data["timeout"] = float(data["timeout"])
    if "max_chars" in data:
        data["max_chars"] = int(data["max_chars"])
    if data.get("log_path") in ("", "off", "none"):
        data["log_path"] = None
    cfg = Config(**data)
    _ = cfg.endpoint  # validate provider early
    if not cfg.sanitize:
        print("jev-sanitizer: WARNING sanitize=false — data will be sent WITHOUT masking", file=sys.stderr)
    return cfg
