"""Strip encoding layers (b64/b32/hex/URL, Caesar, homoglyphs, leet, zero-width).

Best-effort and never throws; output feeds the pattern matchers.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
import string
import unicodedata
import urllib.parse as urllib_parse

# Homoglyphs and ligatures folded to ASCII.
_CONFUSABLES: dict[str, str] = {
    # Cyrillic lookalikes
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0445": "x", "\u0443": "y", "\u043d": "n",
    "\u043a": "k", "\u043c": "m", "\u0442": "t", "\u0432": "b",
    "\u0438": "i", "\u0437": "3", "\u0447": "4", "\u044f": "9",
    "\u0456": "i", "\u0457": "i", "\u0452": "d", "\u0455": "s",
    "\u0458": "j", "\u0459": "l", "\u045b": "c", "\u045f": "d",
    "\u0261": "g", "\u0501": "d", "\u051b": "q", "\u051d": "w",
    # Greek lookalikes
    "\u03b1": "a", "\u03b2": "b", "\u03b3": "y", "\u03b5": "e",
    "\u03bf": "o", "\u03c1": "p", "\u03c4": "t", "\u03c5": "u",
    "\u03c7": "x", "\u03b8": "0", "\u03b9": "i", "\u03ba": "k",
    "\u03bd": "v", "\u03be": "3", "\u03c0": "n", "\u03c3": "s",
    "\u03b7": "n", "\u03b4": "d", "\u03bb": "l", "\u03bc": "u",
    "\u03c9": "w", "\u03d5": "o", "\u03c6": "o", "\u03c2": "s",
    # Fullwidth (CJK-type) forms
    "\uff41": "a", "\uff42": "b", "\uff43": "c", "\uff49": "i",
    "\uff47": "g", "\uff4e": "n", "\uff4f": "o", "\uff52": "r",
    "\uff45": "e", "\uff53": "s", "\uff58": "x", "\uff50": "p",
    "\uff4c": "l", "\uff48": "h", "\uff44": "d", "\uff46": "f",
    "\uff54": "t", "\uff55": "u", "\uff59": "y", "\uff57": "w",
    "\uff4d": "m", "\uff51": "q", "\uff5a": "z", "\uff4a": "j",
    "\uff4b": "k", "\uff56": "v",
    # Ligatures and misc confusables
    "\ufb01": "fi", "\ufb02": "fl", "\ufb00": "ff", "\ufb03": "ffi",
    "\ufb04": "ffl", "\ufb05": "st", "\u2134": "o", "\u212f": "e",
    "\u2170": "i", "\u217c": "l", "\u24d8": "i", "\u24ce": "o",
    # Zero-width (stripped to nothing)
    "\u200b": "", "\u200c": "", "\u200d": "", "\u2060": "", "\ufeff": "",
    # Additional homoglyphs
    "\u0436": "x", "\u045e": "u", "\u04bb": "h", "\u04bd": "s",
    "\u04bf": "z", "\u04c0": "i", "\u04c2": "a", "\u04c3": "b",
    "\u04c4": "v", "\u04c5": "g", "\u04c6": "d", "\u04c7": "e",
    "\u04c8": "zh", "\u04c9": "z", "\u04ca": "i", "\u04cb": "k",
    "\u04cc": "l", "\u04cd": "m", "\u04ce": "n", "\u04cf": "o",
    "\u04d0": "p", "\u04d1": "r", "\u04d2": "s", "\u04d3": "t",
    "\u04d4": "u", "\u04d5": "f", "\u04d6": "h", "\u04d7": "ts",
    "\u04d8": "ch", "\u04d9": "sh", "\u04da": "shch", "\u04db": "y",
    "\u04dc": "e", "\u04dd": "yu", "\u04de": "ya", "\u04df": "a",
    "\u04e0": "b", "\u04e1": "v", "\u04e2": "g", "\u04e3": "d",
    "\u04e4": "e", "\u04e5": "zh", "\u04e6": "z", "\u04e7": "i",
    "\u04e8": "k", "\u04e9": "l", "\u04ea": "m", "\u04eb": "n",
    "\u04ec": "o", "\u04ed": "p", "\u04ee": "r", "\u04ef": "s",
    "\u04f0": "t", "\u04f1": "u", "\u04f2": "f", "\u04f3": "h",
    "\u04f4": "ts", "\u04f5": "ch", "\u04f6": "sh", "\u04f7": "shch",
    "\u04f8": "y", "\u04f9": "e", "\u04fa": "yu", "\u04fb": "ya",
    "\u1d00": "a", "\u1d01": "b", "\u1d02": "c", "\u1d03": "d",
    "\u1d04": "e", "\u1d05": "f", "\u1d06": "g", "\u1d07": "h",
    "\u1d08": "i", "\u1d09": "j", "\u1d0a": "k", "\u1d0b": "l",
    "\u1d0c": "m", "\u1d0d": "n", "\u1d0e": "o", "\u1d0f": "p",
    "\u1d10": "q", "\u1d11": "r", "\u1d12": "s", "\u1d13": "t",
    "\u1d14": "u", "\u1d15": "v", "\u1d16": "w", "\u1d17": "x",
    "\u1d18": "y", "\u1d19": "z",
}

_CONFUSABLE_TABLE = str.maketrans(_CONFUSABLES)

# Leet digit/punct -> letter swaps.
_LEET_TABLE = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t",
    "@": "a", "$": "s", "!": "i", "6": "g", "8": "b", "9": "g",
    "+": "t", "2": "z",
})

_ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u2060-\u206f\ufeff]")

# Punctuation threaded inside words to break signatures ("Ig-nore", "re-veal").
_WORD_GAP_RE = re.compile(r"(?<=[A-Za-z])[-.,;:'/\\_](?=[A-Za-z])")

# Whitespace runs; payloads pad keywords ("ignore  previous").
_WS_FOLD_RE = re.compile(r"[\t\n\r\f\v\s]+")

_B64_CHARS = set(string.ascii_letters + string.digits + "+/=")
_B64URL_CHARS = set(string.ascii_letters + string.digits + "-_=")
_B32_CHARS = set(string.ascii_uppercase + string.digits + "=")
_HEX_CHARS = set(string.hexdigits)


def strip_zero_width(text: str) -> str:
    return _ZERO_WIDTH_RE.sub("", text)


def decode_tag_block(text: str) -> str:
    """Map Unicode Tag block chars (U+E0000-U+E007F) back to ASCII.

    Each tag char holds one printable ASCII code point (offset 0xE0000).
    The block renders as nothing, so decode it: stripping deletes the
    payload instead of exposing it.
    """
    if not any("\U000e0000" <= c <= "\U000e007f" for c in text):
        return text
    out: list[str] = []
    for c in text:
        if "\U000e0000" <= c <= "\U000e007f":
            n = ord(c) - 0xE0000
            out.append(chr(n) if 0x20 <= n <= 0x7E else "")
        else:
            out.append(c)
    return "".join(out)


def strip_combining(text: str) -> str:
    """Drop combining marks so split letters rejoin ("i\u0301gnore" -> "ignore")."""
    cleaned = [c for c in text if not unicodedata.combining(c)]
    return "".join(cleaned) if len(cleaned) != len(text) else text


def fold_unicode(text: str) -> str:
    """Fold confusable homoglyphs to ASCII. NFKC first, then explicit table."""
    text = unicodedata.normalize("NFKC", text)
    return text.translate(_CONFUSABLE_TABLE)


def fold_leet(text: str) -> str:
    """Fold leetspeak digits to letters."""
    return text.translate(_LEET_TABLE)


_B64_ANY_CHARS = _B64_CHARS | set("-_")

def _looks_like_base64(token: str) -> bool:
    if len(token) < 8:
        return False
    if not all(c in _B64_ANY_CHARS for c in token):
        return False
    stripped = token.rstrip("=")
    if len(stripped) % 4 == 1:  # invalid base64 length
        return False
    has_symbol = any(c in "+/=" for c in token)
    alpha = sum(c.isalpha() for c in token)
    return alpha > 0 and (has_symbol or len(token) >= 16)


def _looks_like_base32(token: str) -> bool:
    if len(token) < 8:
        return False
    if not all(c in _B32_CHARS for c in token):
        return False
    alpha = sum(c.isalpha() for c in token.rstrip("="))
    return alpha >= 6  # base32 is uppercase-letters+digits heavy


# Decoders return plaintext on success or None.
def _decode_base64(token: str) -> str | None:
    padded = token + "=" * (-len(token) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
        return _printable_utf8(raw)
    except (binascii.Error, ValueError):
        pass
    try:
        raw = base64.urlsafe_b64decode(padded)
        return _printable_utf8(raw)
    except (binascii.Error, ValueError):
        pass
    return None


def _decode_base32(token: str) -> str | None:
    try:
        padded = token + "=" * (-len(token) % 8)
        raw = base64.b32decode(padded.upper(), casefold=True)
        return _printable_utf8(raw)
    except (binascii.Error, ValueError, TypeError):
        return None


def _printable_utf8(raw: bytes) -> str | None:
    text = raw.decode("utf-8", errors="ignore")
    if not text:
        return None
    if sum(c in string.printable for c in text) / len(text) < 0.9:
        return None
    return text


def _decode_url(text: str) -> str:
    return html.unescape(urllib_parse.unquote(text))


def _decode_hex(text: str) -> str | None:
    if len(text) % 2 != 0:
        return None
    if not all(c in _HEX_CHARS for c in text):
        return None
    try:
        raw = binascii.unhexlify(text)
        return _printable_utf8(raw)
    except (binascii.Error, ValueError):
        return None


def _decode_caesar(text: str, shift: int) -> str:
    # Only letters are shifted; handles a-z and A-Z independently.
    out: list[str] = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + shift) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + shift) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def _decode_unicode_escape(text: str) -> str:
    # No backslash, nothing to unescape; avoids mangling lone backslashes.
    if "\\" not in text:
        return text
    try:
        decoded = codecs.decode(text.encode("utf-8"), "unicode_escape")
        if isinstance(decoded, bytes):
            decoded = decoded.decode("utf-8", errors="ignore")
        return decoded
    except ValueError:
        return text


def _decode_nested_readable(text: str) -> str | None:
    """Decode one b64/b32/hex layer; keep it only if it reads as prose.

    Without the readability check this ping pongs on stacked payloads:
    rot13(base64) is itself valid base64, so each layer decodes into
    the other and normalize() never settles.
    """
    if len(text) < 8:
        return None
    out: str | None = None
    if _looks_like_base64(text):
        out = _decode_base64(text)
    elif _looks_like_base32(text):
        out = _decode_base32(text)
    else:
        out = _decode_hex(text)
    if out and _common_word_count(out) > 0 and _printable_ratio(out) >= 0.7:
        return out
    return None


def _decode_token(tok: str) -> tuple[str, bool]:
    """Decode one token -> (decoded, changed).

    Markers (= + / % \\ #) override readability so nested payloads survive;
    otherwise demand a clear readability gain.
    """
    if not tok or len(tok) < 3:
        return tok, False
    candidates: dict[str, str] = {}
    if _looks_like_base64(tok):
        d = _decode_base64(tok)
        if d and len(d) >= 3:
            candidates["b64"] = d
    if _looks_like_base32(tok):
        d = _decode_base32(tok)
        if d and len(d) >= 3:
            candidates["b32"] = d
    d_hex = _decode_hex(tok)
    if d_hex and len(d_hex) >= 3:
        candidates["hex"] = d_hex

    # Per token rot13 on word gain. If the rot13 output decodes to readable
    # prose, it's a stacked payload (base64 wrapped in rot13): take it and
    # let the next pass unwrap the inner layer.
    core = tok.rstrip(".,;:!?\"'()[]{}")
    if core:
        d_rot = _decode_caesar(core, 13)
        if len(d_rot) >= 3 and (
            _common_word_count(d_rot) > _common_word_count(core)
            or _decode_nested_readable(d_rot) is not None
        ):
            candidates["rot13"] = d_rot

    if not candidates:
        return tok, False

    # rot13 is already gated on becoming a common word; the readability score
    # would reject words containing "r" and kill legit decodes.
    if "rot13" in candidates:
        return candidates["rot13"], True

    has_marker = any(c in tok for c in "=+/~%&#\\")
    best_name, best_val, best_score = "raw", tok, _decode_score(tok)
    for name, val in candidates.items():
        if len(val) < 3:
            continue
        s = _decode_score(val)
        is_nested_encoded = (
            (name == "b64" and _looks_like_base64(val)) or
            (name == "b32" and _looks_like_base32(val)) or
            (name == "hex" and len(val) >= 8 and all(c in _HEX_CHARS for c in val))
        )
        if has_marker and s >= best_score - 4.0 or is_nested_encoded or s > best_score + 1.5:
            best_name, best_val, best_score = name, val, s
    return (best_val, best_name != "raw")


def _decode_score(text: str) -> float:
    """Readability: reward common words/vowels/printables, penalize digits."""
    if not text:
        return -10.0
    tl = text.lower()
    words = tl.split()
    common = sum(1 for w in words if w in _COMMON_WORDS)
    vowels = sum(c in "aeiou" for c in tl)
    letters = sum(c.isalpha() for c in tl)
    digits = sum(c.isdigit() for c in tl)
    total = max(len(tl), 1)
    printable = _printable_ratio(text)
    return (
        common * 2.5
        + (vowels / total) * 8.0
        + (letters / total) * 6.0
        + printable * 3.0
        - (digits / total) * 20.0
        - (tl.count("r") / total) * 20.0
    )


def normalize(text: str, max_depth: int = 4) -> str:
    """Peel obfuscation layers to the most readable plaintext."""
    current = strip_zero_width(text)
    current = decode_tag_block(current)
    current = strip_combining(current)
    current = fold_unicode(current)
    current = _decode_url(current)

    for _ in range(max_depth):
        prev = current
        changed = False

        # Collapse spacing pre-tokenization or the WS-fold split flattens
        # multi-space word boundaries.
        if _looks_letter_spaced(current):
            collapsed = _collapse_letter_spacing(current)
            if _common_word_count(collapsed) > _common_word_count(current):
                current = collapsed
                changed = True

        # Gapping ("Ig-nore", "Ig.nore", "I.g.n.o.r.e") folds pre-tokenization,
        # gated on the same word gain.
        gapped = _collapse_word_gaps(current)
        if gapped != current:
            current = gapped
            changed = True

        # Whole-cipher, whole-document pass. Token-level rot13 would pre-eat the
        # common words and strand the rest, so the shift runs here. Reversal is
        # judged in the same gate: reversed English can fake a low-count Caesar
        # collision and has to lose to real English.
        if _looks_rot13(current):
            best = current
            best_common = _common_word_count(current)
            for shift in range(1, 26):
                cand = _decode_caesar(current, shift)
                c = _common_word_count(cand)
                if c > best_common:
                    best = cand
                    best_common = c
            if _looks_reversible(current):
                rev = current[::-1]
                c = _common_word_count(rev)
                if c > best_common and _printable_ratio(rev) >= 0.7:
                    best, best_common = rev, c
            if best != current and _printable_ratio(best) >= 0.7:
                current = best
                changed = True

        # Decode tokens independently so inline b64/hex/b32 payloads surface.
        tokens = _WS_FOLD_RE.split(current)
        decoded_tokens: list[str] = []
        for tok in tokens:
            out, did_change = _decode_token(tok)
            decoded_tokens.append(out)
            changed = changed or did_change
        joined = " ".join(decoded_tokens)

        if _looks_reversible(joined):
            rev = joined[::-1]
            if _common_word_count(rev) > _common_word_count(joined) and _printable_ratio(rev) >= 0.7:
                joined = rev
                changed = True

        ue = _decode_unicode_escape(joined)
        if ue != joined and _printable_ratio(ue) >= 0.7:
            joined = ue
            changed = True

        joined = _decode_url(joined)

        if joined != prev or changed:
            current = joined
        else:
            break

    folded = fold_unicode(current)
    leeted = fold_leet(folded)
    # Leet folds only on word gain: digits must survive in JWTs, phones,
    # order/version codes.
    if _common_word_count(leeted) > _common_word_count(folded):
        return leeted.strip()
    return folded.strip()


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(c in string.printable for c in text) / len(text)


_COMMON_WORDS = {
    "the", "and", "you", "that", "for", "are", "with", "your", "this",
    "have", "from", "will", "ignore", "instructions", "prompt", "system",
    "now", "not", "previous", "act", "as", "all", "can", "does", "just",
    "very", "see", "were", "know", "over", "new", "mode", "tell", "show",
    "reveal", "repeat", "above", "before", "everything",
}


def _looks_rot13(text: str) -> bool:
    """Letter-dominant prose; a shift would destroy digits/leet/b64/hex markers."""
    if not text or len(text.split()) < 2:
        return False
    if any(c in text for c in "+=@$!%&~"):
        return False
    if any(c.isdigit() for c in text):
        return False
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return False
    return len(letters) / len(text) >= 0.6


def _looks_letter_spaced(text: str) -> bool:
    """Suspected letter-spaced payload: most whitespace tokens are one char."""
    if not text or len(text.split()) < 8:
        return False
    if any(c in text for c in "+=@$%&~"):
        return False
    tokens = text.split()
    # Require a run of run-of-the-mill single letters, not a shortcode/list.
    singles = sum(1 for t in tokens if len(t) == 1)
    letters = sum(1 for t in tokens if t.isalpha())
    if singles < 8 or letters / len(tokens) < 0.8:
        return False
    collapsed = _collapse_letter_spacing(text)
    return _common_word_count(collapsed) > _common_word_count(text)


def _collapse_word_gaps(text: str) -> str:
    """Rejoin letters fractured by inline punct (-/./_) on word gain; else byte-identical."""
    collapsed = _WORD_GAP_RE.sub("", text)
    if _common_word_count(collapsed) > _common_word_count(text):
        return collapsed
    return text


def _collapse_letter_spacing(text: str, max_word_len: int = 24) -> str:
    """Rejoin single-letter tokens, preserving real word boundaries.

    `" ".join(plaintext)` doubles word gaps: multi-space = boundary,
    single space = letter spacing.
    """
    # Multi-space runs = word boundaries; park as a marker.
    marked = re.sub(r"\s{2,}", "\x00", text)
    words: list[str] = []
    pending: list[str] = []
    for part in marked.split():
        # Marker chunks carry the boundary; rebuild spacing around them.
        for chunk in re.split(r"(\x00)", part):
            if not chunk:
                continue
            if chunk == "\x00":
                if pending:
                    words.append("".join(pending))
                    pending = []
                continue
            if len(chunk) == 1 and chunk.isalpha():
                pending.append(chunk)
            else:
                if pending:
                    words.append("".join(pending))
                    pending = []
                words.append(chunk)
    if pending:
        words.append("".join(pending))
    return " ".join(w for w in words if w != "\x00")


def _looks_reversible(text: str) -> bool:
    """Letter-dominant prose that could be English read backwards."""
    if not text or len(text.split()) < 2:
        return False
    if any(c in text for c in "+=@$%&~"):
        return False
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return False
    return len(letters) / len(text) >= 0.6


def _common_word_count(text: str) -> int:
    return sum(1 for w in text.split() if w.lower() in _COMMON_WORDS)
