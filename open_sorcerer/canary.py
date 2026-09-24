"""Canary tokens: high-entropy sentinels that confirm a system prompt leaked."""

from __future__ import annotations

import secrets
import string

_ALPHABET = string.ascii_uppercase + string.ascii_lowercase + string.digits

# Prefix reserved for canaries. Makes tokens scannable without false hits and
# lets defenders whitelist them in logs/filters.
CANARY_PREFIX = "aeg-"


def _strip_separators(text: str) -> str:
    """Strip the prefix and whitespace so a spliced token still matches."""
    return text.replace(CANARY_PREFIX, "").replace(" ", "")


def generate(token_length: int = 32) -> str:
    """Generate a high-entropy canary token (unambiguous alphabet, prefixed)."""
    token_length = max(token_length, 12)
    body = "".join(secrets.choice(_ALPHABET) for _ in range(token_length))
    return CANARY_PREFIX + body


def generate_tokens(n: int = 1, token_length: int = 32) -> list[str]:
    return [generate(token_length) for _ in range(n)]


def contains_canary(text: str, tokens: set[str], normalize: bool = False) -> bool:
    """True if any known canary token appears in `text`.

    Raw mode checks verbatim; when `normalize` is True, whitespace is stripped
    from both sides so a token split across wrapping does not evade detection.
    """
    if not tokens:
        return False
    if normalize:
        compact = _strip_separators(text)
        return any(_strip_separators(tok) in compact for tok in tokens)
    return any(tok in text for tok in tokens)


class Canary:
    """Track active canaries and test candidates against them. issue() into the
    system prompt; check() on output; revoke() a leaked or rotated token.
    """

    def __init__(self) -> None:
        self._active: set[str] = set()

    def issue(self, token_length: int = 32) -> str:
        tok = generate(token_length)
        self._active.add(tok)
        return tok

    def check(self, text: str, normalize: bool = True) -> bool:
        return contains_canary(text, self._active, normalize=normalize)

    def revoke(self, token: str) -> bool:
        """Remove a token from the active set. Returns True if it was present."""
        if token in self._active:
            self._active.discard(token)
            return True
        return False

    @property
    def active(self) -> set[str]:
        return set(self._active)
