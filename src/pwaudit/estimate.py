"""How many guesses would an attacker who knows common patterns need?

This is a compact, pattern-aware estimator in the spirit of zxcvbn (Wheeler, USENIX Security 2016):
instead of "8 characters with a digit and a symbol = strong", it finds the cheapest way an
attacker's tool would build the password out of known pieces: common passwords and words
(with capital letters and leetspeak undone), keyboard walks, sequences, repeats, years and dates,
and plain brute force for whatever is left. The estimate is the number of guesses of that cheapest
decomposition. It is an estimate of *typical cracking tools*, not a proof of strength.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import lru_cache

from .keyboard import QWERTY, graph_stats
from .wordlists import COMMON_PASSWORDS, COMMON_WORDS

MAX_ANALYSED = 72  # past this the rest is counted as brute force: no password needs more
REFERENCE_YEAR = 2026
MIN_YEAR_GUESSES = 20

LEET = {
    "@": "a",
    "4": "a",
    "8": "b",
    "(": "c",
    "{": "c",
    "[": "c",
    "3": "e",
    "6": "g",
    "9": "g",
    "1": "il",
    "!": "il",
    "|": "il",
    "0": "o",
    "$": "s",
    "5": "s",
    "7": "t",
    "+": "t",
    "2": "z",
}

_RANKS: dict[str, tuple[str, int]] = {}
for _i, _w in enumerate(COMMON_PASSWORDS, 1):
    _RANKS.setdefault(_w, ("password", _i))
for _i, _w in enumerate(COMMON_WORDS, len(COMMON_PASSWORDS) + 1):
    _RANKS.setdefault(_w, ("word", _i))

# Guesses below which the score is 0, 1, 2, 3 (4 above the last). Read against RATES: 0 falls to an
# unthrottled online attack within a day, 1 to an offline attack on a slow hash within a day,
# 2 needs more than a day on a slow hash, 3 survives minutes to hours on a fast-hash rig,
# 4 survives about a week of a 10-billion-guesses-per-second rig.
SCORE_LIMITS = (1e6, 1e9, 1e12, 1e16)


@dataclass(frozen=True)
class Match:
    i: int  # first character, inclusive
    j: int  # last character, inclusive
    kind: str  # dictionary | spatial | sequence | repeat | year | date | bruteforce
    guesses: float
    token: str = field(repr=False, default="")
    detail: str = ""

    @property
    def length(self) -> int:
        return self.j - self.i + 1


@dataclass(frozen=True)
class Result:
    guesses: float
    score: int  # 0 (trivial) .. 4 (very strong)
    matches: tuple[Match, ...]
    length: int = 0

    @property
    def bits(self) -> float:
        return math.log2(max(self.guesses, 1.0))


def load_wordlist(path: str, limit: int = 5_000_000) -> int:
    """Add a wordlist (one word per line, most common first, e.g. a leaked-password list) to the
    dictionaries. Words already known keep their better rank. Returns the number of words added."""
    added = 0
    base = len(_RANKS) + 1
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            word = line.rstrip("\r\n").lower()
            if word and word not in _RANKS and len(word) <= MAX_ANALYSED:
                _RANKS[word] = ("wordlist", base + added)
                added += 1
                if added >= limit:
                    break
    _cached.cache_clear()
    return added


def _comb(n: int, k: int) -> int:
    return math.comb(n, k) if 0 <= k <= n else 0


def cardinality(password: str) -> int:
    size = 0
    if re.search(r"[a-z]", password):
        size += 26
    if re.search(r"[A-Z]", password):
        size += 26
    if re.search(r"[0-9]", password):
        size += 10
    if re.search(r"[ -/:-@\[-`{-~]", password):
        size += 33
    if re.search(r"[^\x00-\x7f]", password):
        size += 100
    return max(size, 10)


def _segment_cardinality(segment: str, whole: int) -> int:
    """Alphabet an attacker needs for this piece. A run of two or more characters from one class
    (digits after a word, say) is what mask and hybrid attacks go for; anything mixed costs the
    alphabet of the whole password, because an attacker does not know where the classes change."""
    if len(segment) >= 2:
        own = cardinality(segment)
        if own in (10, 26, 33):
            return own
    return whole


# --- matchers ---------------------------------------------------------------------------


def _uppercase_variants(token: str) -> float:
    if token.islower() or not any(c.isalpha() for c in token):
        return 1.0
    if (
        re.fullmatch(r"[A-Z][^A-Z]*", token)
        or token.isupper()
        or re.fullmatch(r"[^A-Z]*[A-Z]", token)
    ):
        return 2.0
    upper = sum(c.isupper() for c in token)
    lower = sum(c.islower() for c in token)
    return float(sum(_comb(upper + lower, k) for k in range(1, min(upper, lower) + 1)) or 2)


def _leet_candidates(token: str) -> Iterable[tuple[str, float]]:
    """(plain text, variation factor) for the token with every leet character undone."""
    lowered = token.lower()
    if not any(c in LEET for c in lowered):
        return
    for choice in ("a", "i"):  # 1 and ! can stand for i or l
        plain = []
        for c in lowered:
            subs = LEET.get(c)
            plain.append(c if subs is None else (choice if choice in subs else subs[0]))
        text = "".join(plain)
        if text == lowered:
            continue
        factor = 1.0
        for c in set(c for c in lowered if c in LEET):
            substituted = lowered.count(c)
            unchanged = sum(1 for p in lowered if p == LEET[c][0] or p in LEET[c])
            factor *= max(
                2.0,
                float(
                    sum(
                        _comb(substituted + unchanged, k)
                        for k in range(1, min(substituted, unchanged) + 1)
                    )
                ),
            )
        yield text, factor


def dictionary_matches(password: str, extra: dict[str, int]) -> list[Match]:
    out: list[Match] = []
    n = len(password)
    for i in range(n):
        for j in range(i + 1, n):
            token = password[i : j + 1]
            lowered = token.lower()
            variants: list[tuple[str, float, str]] = [(lowered, 1.0, "")]
            variants += [(t, f, "leet") for t, f in _leet_candidates(token)]
            variants += [(lowered[::-1], 2.0, "reversed")]
            for text, factor, how in variants:
                if text in extra:
                    rank, name = extra[text], "context"
                elif text in _RANKS and (len(text) >= 3 or _RANKS[text][0] == "password"):
                    name, rank = _RANKS[text]
                else:
                    continue
                guesses = rank * factor * _uppercase_variants(token)
                out.append(
                    Match(
                        i,
                        j,
                        "dictionary",
                        guesses,
                        token,
                        f"{name} #{rank}" + (f", {how}" if how else ""),
                    )
                )
    return out


def _walk_guesses(length: int, turns: int, shifted: int, adjacency: str) -> float:
    start, degree = graph_stats(adjacency)
    total = 0.0
    for i in range(2, length + 1):
        for t in range(1, min(turns, i - 1) + 1):
            total += _comb(i - 1, t - 1) * start * degree**t
    if shifted:
        unshifted = length - shifted
        total *= (
            2
            if unshifted == 0 or shifted == 0
            else sum(_comb(length, k) for k in range(1, min(shifted, unshifted) + 1))
        )
    return total


def spatial_matches(password: str) -> list[Match]:
    out: list[Match] = []
    n = len(password)
    i = 0
    while i < n - 2:
        j = i + 1
        last_dir = -1
        turns = 0
        shifted = 1 if QWERTY.is_shifted(password[i]) else 0
        while j < n:
            direction = QWERTY.direction(password[j - 1], password[j])
            if direction < 0:
                break
            if direction != last_dir:
                turns += 1
                last_dir = direction
            if QWERTY.is_shifted(password[j]):
                shifted += 1
            j += 1
            if j - i >= 3:
                out.append(
                    Match(
                        i,
                        j - 1,
                        "spatial",
                        _walk_guesses(j - i, turns, shifted, "qwerty"),
                        password[i:j],
                        f"qwerty walk, {turns} turns",
                    )
                )
        i = j - 1 if j - i > 1 else i + 1
    return out


def sequence_matches(password: str) -> list[Match]:
    out: list[Match] = []
    n = len(password)
    for i in range(n - 2):
        delta = ord(password[i + 1]) - ord(password[i])
        if delta == 0 or abs(delta) > 5:
            continue
        if i > 0 and ord(password[i]) - ord(password[i - 1]) == delta:
            continue  # starts inside a longer run; the run is found from its first character
        j = i + 1
        while j < n and ord(password[j]) - ord(password[j - 1]) == delta:
            j += 1
        if j - i >= 3:
            first = password[i]
            base = 4.0 if first in "aAzZ019" else 10.0 if first.isdigit() else 26.0
            if delta < 0:
                base *= 2
            out.append(
                Match(i, j - 1, "sequence", base * (j - i), password[i:j], f"step {delta:+d}")
            )
    return out


def repeat_matches(password: str) -> list[Match]:
    out: list[Match] = []
    for m in re.finditer(r"(.+?)\1+", password):
        base = m.group(1)
        count = len(m.group(0)) // len(base)
        inner = most_guessable(base).guesses
        out.append(
            Match(m.start(), m.end() - 1, "repeat", inner * count, m.group(0), f"{base!r} x{count}")
        )
    return out


def _valid_date(a: int, b: int, year: int) -> bool:
    return 1000 <= year <= 2099 and (
        (1 <= a <= 31 and 1 <= b <= 12) or (1 <= b <= 31 and 1 <= a <= 12)
    )


def date_matches(password: str) -> list[Match]:
    out: list[Match] = []
    for m in re.finditer(r"(?<!\d)(19\d\d|20\d\d)(?!\d)", password):
        year = int(m.group(1))
        gap = max(abs(REFERENCE_YEAR - year), MIN_YEAR_GUESSES)
        out.append(Match(m.start(), m.end() - 1, "year", float(gap), m.group(0), "year"))
    # (regex, separated, order of the groups: which is day-or-month, month-or-day, year)
    patterns = [
        (r"(?<!\d)(\d{1,2})([/\-. ])(\d{1,2})\2(\d{4}|\d{2})(?!\d)", True, (0, 2, 3)),
        (r"(?<!\d)(\d{2})(\d{2})(\d{4})(?!\d)", False, (0, 1, 2)),
        (r"(?<!\d)(\d{4})(\d{2})(\d{2})(?!\d)", False, (1, 2, 0)),
        (r"(?<!\d)(\d{2})(\d{2})(\d{2})(?!\d)", False, (0, 1, 2)),
    ]
    for pattern, separated, order in patterns:
        for m in re.finditer(pattern, password):
            groups = m.groups()
            a, b, y = (int(groups[k]) for k in order)
            if y < 100:
                y += 2000 if y < 40 else 1900
            if not _valid_date(a, b, y):
                continue
            guesses = (
                365.0 * max(abs(REFERENCE_YEAR - y), MIN_YEAR_GUESSES) * (4 if separated else 1)
            )
            out.append(Match(m.start(), m.end() - 1, "date", guesses, m.group(0), "date"))
    return out


# --- the search --------------------------------------------------------------------------


def _factorial(n: int) -> float:
    return float(math.factorial(n))


@lru_cache(maxsize=4096)
def _cached(password: str, extra: tuple[tuple[str, int], ...]) -> Result:
    return _most_guessable(password, dict(extra))


def most_guessable(password: str, extra: dict[str, int] | None = None) -> Result:
    return _cached(password, tuple(sorted((extra or {}).items())))


def _most_guessable(password: str, extra: dict[str, int]) -> Result:
    if not password:
        return Result(1.0, 0, (), 0)
    head = password[:MAX_ANALYSED]
    n = len(head)
    card = cardinality(password)
    matches = (
        dictionary_matches(head, extra)
        + spatial_matches(head)
        + sequence_matches(head)
        + repeat_matches(head)
        + date_matches(head)
    )
    by_end: list[list[Match]] = [[] for _ in range(n)]
    for m in matches:
        by_end[m.j].append(m)
    for j in range(n):
        for i in range(j + 1):
            segment = head[i : j + 1]
            by_end[j].append(
                Match(
                    i,
                    j,
                    "bruteforce",
                    float(_segment_cardinality(segment, card)) ** len(segment),
                    segment,
                    "",
                )
            )

    # best[k][pieces] = (product of the pieces' guesses, the pieces) covering head[: k + 1]
    best: list[dict[int, tuple[float, tuple[Match, ...]]]] = [{} for _ in range(n)]
    for k in range(n):
        for m in by_end[k]:
            before: list[tuple[int, float, tuple[Match, ...]]]
            if m.i == 0:
                before = [(0, 1.0, ())]
            else:
                before = [(pieces, prod, ms) for pieces, (prod, ms) in best[m.i - 1].items()]
            for pieces, prod, ms in before:
                product = prod * m.guesses
                current = best[k].get(pieces + 1)
                if current is None or product < current[0]:
                    best[k][pieces + 1] = (product, (*ms, m))
    total = math.inf
    chosen: tuple[Match, ...] = ()
    for length, (product, ms) in best[n - 1].items():
        guesses = _factorial(length) * product + 10000.0 ** (length - 1)
        if guesses < total:
            total, chosen = guesses, ms
    if len(password) > n:  # the unanalysed tail
        tail = password[n:]
        total *= float(_segment_cardinality(tail, card)) ** len(tail)
    score = sum(total >= limit for limit in SCORE_LIMITS)
    return Result(total, score, chosen, len(password))


def analyse(password: str, context: Iterable[str] = ()) -> Result:
    """Estimate `password`; `context` words (user name, site, ...) are treated as the first
    things an attacker would try."""
    extra: dict[str, int] = {}
    for word in context:
        for part in (*re.split(r"[^\w]+", word.lower()), word.lower()):
            if len(part) >= 3:
                extra.setdefault(part, 2)
    return most_guessable(password, extra)


# --- explaining it -----------------------------------------------------------------------

RATES = (
    ("online, throttled (100 per hour)", 100 / 3600),
    ("online, no throttle (10 per second)", 10.0),
    ("offline, slow hash such as bcrypt (10,000 per second)", 1e4),
    ("offline, fast hash such as SHA-1 on a GPU rig (10 billion per second)", 1e10),
)


def humanise(seconds: float) -> str:
    if seconds < 1:
        return "instantly"
    value = seconds
    for name, size in (
        ("second", 60.0),
        ("minute", 60.0),
        ("hour", 24.0),
        ("day", 30.4),
        ("month", 12.0),
        ("year", 100.0),
    ):
        if value < size:
            n = int(value)
            return f"{n} {name}{'' if n == 1 else 's'}"
        value /= size
    return "centuries"


def crack_times(guesses: float) -> list[tuple[str, str]]:
    return [(label, humanise(guesses / 2 / rate)) for label, rate in RATES]


def feedback(result: Result, password: str) -> list[str]:
    """Plain advice, never quoting the password."""
    tips: list[str] = []
    kinds = {m.kind for m in result.matches}
    for m in result.matches:
        if m.kind == "dictionary" and m.detail.startswith("password"):
            rank = int(m.detail.split("#")[1].split(",")[0])
            if m.length == result.length:
                bucket = next((b for b in (10, 100, 1000) if rank <= b), 0)
                tips.append(
                    f"This is among the {bucket:,} most common passwords."
                    if bucket
                    else "This is a common password."
                )
        elif m.kind == "dictionary" and "context" in m.detail:
            tips.append("It contains the user name or site name: attackers try those first.")
    if "spatial" in kinds:
        tips.append(
            "Keyboard patterns such as qwerty or 1qaz2wsx are in every cracking dictionary."
        )
    if "sequence" in kinds:
        tips.append("Sequences such as abc or 123 are easy to guess.")
    if "repeat" in kinds:
        tips.append("Repeating a short piece adds almost nothing.")
    if kinds & {"year", "date"}:
        tips.append("Dates and years are among the first things tried.")
    if any(m.kind == "dictionary" and "leet" in m.detail for m in result.matches):
        tips.append(
            "Swapping letters for look-alike symbols (a to @, o to 0) is a known trick and does not help much."
        )
    if not tips and result.score <= 2:
        tips.append(
            "Make it longer: a few unrelated words are stronger and easier to remember than symbols."
        )
    if len(password) < 12 and result.score < 4:
        tips.append("Under 12 characters is short for a password that must resist offline attacks.")
    return list(dict.fromkeys(tips))
