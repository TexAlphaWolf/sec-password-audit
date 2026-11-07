#!/usr/bin/env python3
"""Calibrate the estimator against passwords whose construction is known.

Real leaked passwords cannot be bundled, so the evidence is built from generators:

  random      uniform random characters (the estimate must NOT exceed the true search space:
              overestimating strength is the dangerous error)
  words       one common word + digits / a year / a symbol (the classic "strong-looking" password;
              the estimate must call these weak). The words come from the estimator's own
              dictionary, so this shows the pattern logic works when the word is known, not how
              often a real user's word is known: that depends on the dictionary (--wordlist)
  walks       keyboard walks and sequences, with and without a capital or a digit
  dates       dates written in common ways
  leet        common passwords with letters swapped for look-alike symbols
  passphrase  random words joined by a separator (strong, if there are enough words)

    python tools/evaluate.py --n 2000 --seed 7
"""

from __future__ import annotations

import argparse
import math
import random
import statistics
import string
import time

from pwaudit.estimate import analyse
from pwaudit.wordlists import COMMON_PASSWORDS, COMMON_WORDS

ALPHABETS = {
    "lower": string.ascii_lowercase,
    "lower+digit": string.ascii_lowercase + string.digits,
    "mixed": string.ascii_letters + string.digits,
    "printable": string.ascii_letters + string.digits + string.punctuation,  # all 94
}
LEET_SWAPS = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7"}


def random_pw(rng: random.Random, alphabet: str, length: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(length))


def make_words(rng: random.Random) -> str:
    word = rng.choice(COMMON_WORDS)
    word = word.capitalize() if rng.random() < 0.6 else word
    tail = rng.choice(
        [
            str(rng.randrange(10, 100)),
            str(rng.randrange(1970, 2026)),
            "!",
            "123",
            str(rng.randrange(100, 1000)) + "!",
            "@" + str(rng.randrange(1, 10)),
        ]
    )
    return word + tail


def make_walk(rng: random.Random) -> str:
    rows = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]
    row = rng.choice(rows)
    start = rng.randrange(0, len(row) - 4)
    walk = row[start : start + rng.randrange(5, len(row) - start + 1)]
    if rng.random() < 0.4:
        walk = walk.capitalize()
    if rng.random() < 0.4:
        walk += str(rng.randrange(0, 100))
    return walk


def make_date(rng: random.Random) -> str:
    d, m, y = rng.randrange(1, 29), rng.randrange(1, 13), rng.randrange(1950, 2012)
    return rng.choice(
        [
            f"{d:02d}{m:02d}{y}",
            f"{d:02d}/{m:02d}/{y}",
            f"{d}.{m}.{y}",
            f"{y}{m:02d}{d:02d}",
            f"{d:02d}{m:02d}{y % 100:02d}",
        ]
    )


def make_leet(rng: random.Random) -> str:
    word = rng.choice(COMMON_PASSWORDS[:300])
    return "".join(LEET_SWAPS.get(c, c) if rng.random() < 0.7 else c for c in word)


def make_passphrase(rng: random.Random, words: int) -> str:
    return rng.choice("-. _").join(rng.choice(COMMON_WORDS) for _ in range(words))


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    rng = random.Random(args.seed)

    print("RANDOM passwords: estimated bits against the true search space (length x log2 alphabet)")
    print(
        f"{'alphabet':<13}{'length':>6}{'true bits':>11}{'mean est.':>11}{'min est.':>10}{'over true':>11}{'score>=3':>10}"
    )
    over_total = total = 0
    for name, alphabet in ALPHABETS.items():
        for length in (8, 12, 16):
            true_bits = length * math.log2(len(alphabet))
            bits, strong, over = [], 0, 0
            for _ in range(args.n):
                result = analyse(random_pw(rng, alphabet, length))
                bits.append(result.bits)
                strong += result.score >= 3
                over += result.bits > true_bits + 0.5
            over_total += over
            total += args.n
            print(
                f"{name:<13}{length:>6}{true_bits:>11.1f}{statistics.mean(bits):>11.1f}{min(bits):>10.1f}{over / args.n:>11.1%}{strong / args.n:>10.1%}"
            )
    print(
        f"\nestimates above the true search space: {over_total} of {total} ({over_total / total:.2%})\n"
    )

    print("PATTERNED passwords: share of each class the estimator rates weak (score 0 or 1)")
    print(f"{'class':<14}{'n':>6}{'weak':>8}{'score 0':>9}{'median bits':>13}")
    for label, make in (
        ("words+digits", make_words),
        ("walks", make_walk),
        ("dates", make_date),
        ("leet", make_leet),
    ):
        scores, bits = [], []
        for _ in range(args.n):
            result = analyse(make(rng))
            scores.append(result.score)
            bits.append(result.bits)
        print(
            f"{label:<14}{args.n:>6}{sum(s <= 1 for s in scores) / args.n:>8.1%}{sum(s == 0 for s in scores) / args.n:>9.1%}{statistics.median(bits):>13.1f}"
        )

    print("\nPASSPHRASES (random common words): score by number of words")
    print(f"{'words':<8}{'median bits':>13}{'score>=3':>10}{'score 4':>9}")
    for count in (2, 3, 4, 5, 6):
        results = [analyse(make_passphrase(rng, count)) for _ in range(args.n)]
        print(
            f"{count:<8}{statistics.median(r.bits for r in results):>13.1f}{sum(r.score >= 3 for r in results) / args.n:>10.1%}{sum(r.score == 4 for r in results) / args.n:>9.1%}"
        )

    sample = [random_pw(rng, ALPHABETS["printable"], 14) for _ in range(5000)]
    start = time.perf_counter()
    for pw in sample:
        analyse(pw)
    took = time.perf_counter() - start
    print(f"\nspeed: {len(sample) / took:,.0f} passwords/s (14 random characters, single thread)")


if __name__ == "__main__":
    main()
