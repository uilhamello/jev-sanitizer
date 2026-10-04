"""jev-sanitizer — unofficial Jev (TypeSafe) client that sanitizes every request by default."""
__version__ = "0.2.0"

from .client import JevClient  # noqa: E402
from .config import Config, load_config  # noqa: E402
from text_sanitizer_br import Sanitizer, sanitize  # noqa: E402

__all__ = ["JevClient", "Config", "load_config", "Sanitizer", "sanitize", "__version__"]
