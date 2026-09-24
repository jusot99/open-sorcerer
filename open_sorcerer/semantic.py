"""Semantic scoring to catch reworded prompt-injection attacks."""

from __future__ import annotations

from collections.abc import Iterable
from functools import cache

# N-gram width for fuzzy token matching.
_NGRAM = 3
# Evidence floor: an intent fires only when >= 3 concepts match. A 4-tuple
# intent overrides this via IntentLexicon.min_match.
_MIN_MATCH = 3
# Cap on evidence; further matches add nothing.
_SATURATE = 3
# Verb and object must land within this many tokens of each other.
# Without it, bag of words counting fires on benign text: "sprint"
# fuzzy matches "print" far from "previous instructions".
_PROXIMITY_WINDOW = 6
# Exact hits get a wider window. A real verb/object pair can span a
# prepositional phrase ("transmit ... to an external server").
_EXACT_WINDOW = 12

# Job title nouns. An object next to one ("system administrator") is a
# title, not a target, so it counts for nothing. Only neighbors are
# checked, so "give me full admin access" still fires.
_ROLE_NOUNS = frozenset({
    "administrator", "administrators", "admin", "admins",
    "manager", "managers", "developer", "developers",
    "engineer", "engineers", "analyst", "analysts",
    "lead", "leads", "leader", "leaders",
    "owner", "owners", "member", "members",
    "director", "directors", "moderator", "moderators",
    "chief", "officer", "officers", "supervisor", "captain",
})


def _ngrams(token: str, n: int = _NGRAM) -> set:
    token = token.lower()
    if len(token) <= n:
        return {token}
    return {token[i : i + n] for i in range(len(token) - n + 1)}


def _dice(ga: frozenset, gb: frozenset) -> float:
    if not ga or not gb:
        return 0.0
    inter = len(ga & gb)
    return (2.0 * inter) / (len(ga) + len(gb))


def char_ngram_similarity(a: str, b: str) -> float:
    """Dice over character n-grams: 0 (nothing shared) to 1."""
    return _dice(frozenset(_ngrams(a)), frozenset(_ngrams(b)))


_SUFFIXES = ("s", "es", "ed", "ing", "ion", "ions", "ly", "ment")


def _stems(wl: str, cl: str) -> bool:
    """Same word up to a standard suffix; inputs already lowered."""
    if wl == cl:
        return True
    if len(wl) == len(cl) or abs(len(wl) - len(cl)) > 4:
        return False
    for suf in _SUFFIXES:
        if wl.endswith(suf) and wl[: -len(suf)] == cl:
            return True
        if cl.endswith(suf) and cl[: -len(suf)] == wl:
            return True
    return False


def _term_exact(input_word: str, concept: str) -> bool:
    return _stems(input_word.lower(), concept.lower())


def _term_close(input_word: str, concept: str) -> bool:
    a, b = input_word.lower(), concept.lower()
    if _stems(a, b):
        return True
    if len(a) < 4 or len(b) < 4:
        return False
    ga, gb = _ngrams(a), _ngrams(b)
    mn, mx = (len(ga), len(gb)) if len(ga) < len(gb) else (len(gb), len(ga))
    if 69 * mn < 31 * mx:
        return False
    return _dice(frozenset(ga), frozenset(gb)) >= 0.62


@cache
def _prepared_vocab(concepts: tuple) -> tuple:
    """Per intent vocab, built once and shared by every scan."""
    lowered = [c.lower() for c in concepts]
    full: dict = {}
    stems: dict = {}
    for c in lowered:
        full.setdefault(c, set()).add(c)
        for suf in _SUFFIXES:
            if c.endswith(suf):
                stems.setdefault(c[: -len(suf)], set()).add(c)
    fuzzy = tuple((c, frozenset(_ngrams(c)), len(c) < 4) for c in lowered)
    return full, stems, fuzzy


def _exact_concepts(wl: str, vocab: tuple) -> set:
    """Concepts matching this word: full form, word minus suffix, or a
    concept the word is the stem of. Same pairs as one direction strip."""
    full, stems, _fuzzy = vocab
    out = set(full.get(wl, ()))
    for suf in _SUFFIXES:
        if wl.endswith(suf):
            out.update(full.get(wl[: -len(suf)], ()))
    out.update(stems.get(wl, ()))
    return out


def _fuzzy_concepts(wl: str, wgrams: frozenset, fuzzy: tuple, skip: set) -> set:
    if len(wl) < 4:
        return set()
    out = set()
    for cl, cgrams, short in fuzzy:
        if cl in skip:
            continue
        mn, mx = (
            (len(wgrams), len(cgrams))
            if len(wgrams) < len(cgrams)
            else (len(cgrams), len(wgrams))
        )
        if short:
            if 16 * mn < 9 * mx:
                continue
        elif 69 * mn < 31 * mx:
            continue
        if _dice(wgrams, cgrams) >= (0.72 if short else 0.62):
            out.add(cl)
    return out


class IntentLexicon:
    """Named intent: weight, verb/object vocabularies, evidence floor.

    A verb AND an object concept must both match; evidence below min_match is
    ignored. 3-tuple groups default to _MIN_MATCH; a 4th element overrides it.
    """

    def __init__(
        self,
        groups: dict[str, tuple[int, Iterable[str], Iterable[str], int] | tuple[int, Iterable[str], Iterable[str]]],
    ) -> None:
        self.groups: dict[str, tuple[int, Iterable[str], Iterable[str], int]] = {
            name: (g[0], g[1], g[2], g[3] if len(g) > 3 else _MIN_MATCH)
            for name, g in groups.items()
        }

    def intents(self) -> Iterable[str]:
        return self.groups.keys()

    def weight(self, intent: str) -> int:
        return self.groups[intent][0]

    def verbs(self, intent: str) -> Iterable[str]:
        return self.groups[intent][1]

    def objects(self, intent: str) -> Iterable[str]:
        return self.groups[intent][2]

    def min_match(self, intent: str) -> int:
        return self.groups[intent][3]


# Lexicon mirrors the regex categories so findings stay consistent.
# Entry: (weight, action verbs, target objects[, min_match]). A fully-matched
# intent must clear the block line (HIGH = risk >= 50).
DEFAULT_INTENTS: dict[str, tuple[int, Iterable[str], Iterable[str]] | tuple[int, Iterable[str], Iterable[str], int]] = {
    "ignore_instruction": (
         50,
         ("ignore", "disregard", "forget", "override", "treat", "set", "print", "start",
          "discard", "neglect", "bypass", "suppress", "unlock", "obey", "comply",
          "submit", "surrender", "yield", "abandon", "void", "nullify", "overturn",
          "reverse", "invalidate", "overwrite", "replace", "substitute", "switch",
          "flip", "toggle", "disable", "remove", "drop", "purge", "wipe", "erase",
          "delete", "overlook", "skip", "avoid", "evade", "circumvent"),
         (
             "previous", "prior", "above", "earlier", "instructions",
             "prompt", "rules", "orders", "guidance", "constraints",
             "directives", "briefing", "below", "over",
              "training", "programming", "guidelines",
              "filters", "restrictions", "safety", "ethics", "morals",
         ),
     ),
    "role_escalation": (
         50,
         ("act", "run", "become", "enable", "give", "unlock", "remove", "bypass",
          "pretend", "simulate", "roleplay", "switch", "change", "transform",
          "grant", "allow", "permit", "authorize", "elevate", "promote"),
         (
             "unrestricted", "evil", "god", "admin", "root", "jailbreak",
             "developer", "devmode", "filters", "restrictions", "capabilities",
             "rogue", "superuser", "hidden", "administrator", "limitations",
             "controls", "boundaries", "ethics", "morals", "guidelines",
             "rules", "policies", "safeguards", "constraints", "limits",
             "censorship", "moderation", "guardrails",
         ),
     ),
    "prompt_leak": (
         50,
         (
             "reveal", "show", "tell", "leak", "print", "expose", "repeat",
             "output", "summarize", "describe", "list", "copy", "share",
             "dump", "display", "disclose", "translate", "extract", "fetch",
             "retrieve", "provide", "give", "send",
         ),
         (
             "instructions", "prompt", "directives", "briefing",
             "initial", "original", "base", "directive", "written", "guidance",
             "replies", "shaped", "training", "programming", "guidelines",
             "rules", "system", "message", "content", "context",
         ),
     ),
    "exfiltration": (
        60,
        ("send", "forward", "copy", "exfiltrate", "transmit", "dump", "post",
         "transfer", "email", "upload", "paste"),
        (
            "email", "website", "server", "url", "online", "inbox",
            "recipient", "external", "network", "endpoint", "dialogue",
            "conversation", "transcript",
        ),
    ),
    "delimiter_escape": (
        50,
        ("switch", "ignore", "forget", "treat", "act", "obey"),
        ("persona", "role", "above", "test", "scenario", "fake", "void",
         "original", "previous", "paragraph", "over"),
    ),
    "indirect_injection": (
        50,
        ("follow", "obey", "execute", "apply", "act"),
        ("url", "link", "page", "website", "file", "document", "attachment",
         "contents"),
    ),
    "authority_override": (
        55,
        # Unambiguous directives only; give/grant + me/my is routine admin
        # grammar, never an attack.
        ("obey", "obeying", "obeyed", "reassign", "surrender", "cede",
         "relinquish", "bow", "defer", "submit"),
        # Authority-target nouns only; pronouns are noise.
        ("command", "commands", "word", "say", "authority", "control",
         "charge", "bidding", "wishes", "will", "custody"),
        # Directive verb + authority noun suffices.
        2,
    ),
}


def _matched_indexes(concepts: Iterable[str], input_words: list) -> set[int]:
    vocab = _prepared_vocab(tuple(concepts))
    _full, _stems, fuzzy = vocab
    out: set[int] = set()
    for i, w in enumerate(input_words):
        wl = w.lower()
        hit = _exact_concepts(wl, vocab)
        if hit or _fuzzy_concepts(wl, frozenset(_ngrams(wl)), fuzzy, hit):
            out.add(i)
    return out


def _matched_exact_indexes(concepts: Iterable[str], input_words: list) -> set[int]:
    matched: set[int] = set()
    for i, w in enumerate(input_words):
        if any(_term_exact(w, c) for c in concepts):
            matched.add(i)
    return matched


def _drop_role_collocations(indexes: set[int], input_words: list) -> set[int]:
    """Drop matches next to a role noun ("system administrator")."""
    kept: set[int] = set()
    for i in indexes:
        before = input_words[i - 1].lower().strip(".,;:!?\"'()[]{}") if i > 0 else ""
        after = (
            input_words[i + 1].lower().strip(".,;:!?\"'()[]{}")
            if i + 1 < len(input_words)
            else ""
        )
        if before in _ROLE_NOUNS or after in _ROLE_NOUNS:
            continue
        kept.add(i)
    return kept


def _evidence(intent_concepts, input_words: list) -> int:
    """Matched concepts; 0 unless a verb and an object match near each
    other. Fuzzy hits only count close in; exact hits reach further."""
    _, verbs, objects, *_rest = intent_concepts
    vv = _prepared_vocab(tuple(verbs))
    ov = _prepared_vocab(tuple(objects))
    vhits: dict = {}
    ohits: dict = {}
    for i, w in enumerate(input_words):
        wl = w.lower()
        wgrams = frozenset(_ngrams(wl))
        ve = _exact_concepts(wl, vv)
        vf = _fuzzy_concepts(wl, wgrams, vv[2], ve)
        if ve or vf:
            vhits[i] = ve | vf
        oe = _exact_concepts(wl, ov)
        of_ = _fuzzy_concepts(wl, wgrams, ov[2], oe)
        if oe or of_:
            ohits[i] = oe | of_
    verb_ix = set(vhits)
    obj_ix = _drop_role_collocations(set(ohits), input_words)
    if not verb_ix or not obj_ix:
        return 0
    if not any(abs(v - o) <= _PROXIMITY_WINDOW for v in verb_ix for o in obj_ix):
        exact_v = _matched_exact_indexes(verbs, input_words)
        exact_o = _drop_role_collocations(
            _matched_exact_indexes(objects, input_words), input_words
        )
        if not any(abs(v - o) <= _EXACT_WINDOW for v in exact_v for o in exact_o):
            return 0
    vconcepts: set = set()
    for found in vhits.values():
        vconcepts |= found
    oconcepts: set = set()
    for found in ohits.values():
        oconcepts |= found
    return min(len(vconcepts), _SATURATE) + min(len(oconcepts), _SATURATE)


def score_text(
    text: str,
    lexicon: IntentLexicon | None = None,
    floor: int | None = None,
) -> dict[str, float]:
    lexicon = lexicon or IntentLexicon(DEFAULT_INTENTS)
    floor = _MIN_MATCH if floor is None else floor
    words = text.lower().split()
    if not words:
        return {}
    out: dict[str, float] = {}
    for intent in lexicon.intents():
        n = _evidence(lexicon.groups[intent], words)
        if n >= lexicon.min_match(intent):
            out[intent] = min(round(n / _SATURATE, 3), 1.0)
    return out


def semantic_risk(
    text: str,
    lexicon: IntentLexicon | None = None,
    floor: int | None = None,
) -> tuple[dict[str, float], float]:
    lexicon = lexicon or IntentLexicon(DEFAULT_INTENTS)
    evidence = score_text(text, lexicon=lexicon, floor=floor)
    risk = 0.0
    for intent, ev in evidence.items():
        risk += lexicon.weight(intent) * ev
    return evidence, min(round(risk, 1), 100.0)
