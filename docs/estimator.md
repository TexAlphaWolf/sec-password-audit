# How the estimator works

The question is not "how many character classes does it use?" but **"how many guesses would it take a tool that knows how people really choose passwords?"**

## 1. Find the known pieces

For every substring of the password (up to 72 characters analysed) the estimator looks for:

| Piece | Cost of guessing it |
|---|---|
| **Dictionary**: a common password or word, also reversed, and with leetspeak undone (`@`→a, `0`→o, `$`→s, `1`→i or l, ...) | its rank in the list (rank 1 = `123456`), times the variations: capitalisation (first letter, last letter, all caps cost x2; arbitrary capitals cost more) and the leetspeak substitutions made |
| **Keyboard walk** (`qwerty`, `1qaz2wsx`, `poiuy`) | starting keys x neighbours per key ^ number of turns, summed over shorter walks, times a factor if some keys are shifted |
| **Sequence** (`abcd`, `13579`, `9876`) | a small base times the length |
| **Repeat** (`aaaa`, `abcabc`) | the cost of the repeated piece times the repeat count |
| **Year / date** (`1987`, `15/03/1987`, `150387`) | about 365 x the distance of the year from now (at least 20), x4 with separators |
| **User context** (`--context luca`) | rank 2: the first thing tried |

## 2. Pick the cheapest decomposition

Whatever the pieces do not cover is **brute force**. A run of two or more characters of one class (digits after a word) costs that class's alphabet (10 for digits), because mask and hybrid attacks go straight for it; any mixed leftover costs the alphabet of the whole password, since the attacker does not know where the classes change.

A dynamic program finds the decomposition with the fewest guesses. Splitting a password into more pieces costs a factorial (the attacker must also guess the order), as in zxcvbn: `guesses = pieces! x product(piece guesses) + 10000^(pieces - 1)`.

## 3. Score

| Score | Guesses | Meaning |
|---|---|---|
| 0 trivial | below 10^6 | falls to an unthrottled online attack within a day |
| 1 weak | below 10^9 | falls to an offline attack on a slow hash (bcrypt-like, 10,000 per second) within a day |
| 2 fair | below 10^12 | more than a day on a slow hash, minutes on a fast-hash rig |
| 3 strong | below 10^16 | survives hours to days on a fast-hash rig (10 billion per second) |
| 4 very strong | 10^16 or more | survives about a week of that rig |

The time table prints the average time (half the guesses) for four attack speeds so you can judge for yourself.

## Why not "8 characters, one capital, one symbol"?

Because `Password1!` satisfies that rule and is in every cracking dictionary. NIST SP 800-63B recommends length, a check against known-breached passwords, and **no composition rules**: that is what this tool checks.

## Calibration

`tools/evaluate.py` generates passwords whose construction is known and measures the estimator against them. The result that matters most is the safe direction: across 24,000 uniformly random passwords the estimate **never exceeded the true search space**. CI re-runs this and fails if it ever does.
