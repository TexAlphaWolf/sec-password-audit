from __future__ import annotations

import time
from pathlib import Path

import pytest

from pwaudit import estimate
from pwaudit.estimate import analyse, crack_times, feedback, humanise, load_wordlist
from pwaudit.keyboard import QWERTY


@pytest.mark.parametrize(
    "password",
    [
        "password",
        "123456",
        "qwerty",
        "iloveyou",
        "P@ssw0rd",
        "Password1",
        "1qaz2wsx",
        "letmein",
        "aaaaaaaa",
        "abcdefgh",
        "12345678",
        "ciao",
        "zxcvbnm",
        "p4ssw0rd",
        "dr4gon",
    ],
)
def test_famous_passwords_are_trivial(password):  # type: ignore[no-untyped-def]
    assert analyse(password).score == 0


@pytest.mark.parametrize(
    "password",
    [
        "xK9#mQ2$vL7@pR4",
        "tGv7!pQ#2zLk9wX",
        "correct horse battery staple",
        "vT8&nB3!kW5@dJ2#",
        "plum-ladder-orbit-canyon-9",
    ],
)
def test_long_random_or_passphrase_is_strong(password):  # type: ignore[no-untyped-def]
    assert analyse(password).score >= 3


@pytest.mark.parametrize(
    ("weaker", "stronger"),
    [
        ("password", "password1234567"),
        ("abc123", "abc123xyz789"),
        ("Summer2024!", "Summer2024!Winter2019?"),
        ("hunter2", "hunter2hunter2xy"),
    ],
)
def test_adding_real_entropy_helps(weaker, stronger):  # type: ignore[no-untyped-def]
    assert analyse(stronger).guesses > analyse(weaker).guesses


def test_capitals_and_symbols_do_not_rescue_a_common_word():
    plain = analyse("monkey").guesses
    dressed = analyse("M0nk3y!").guesses
    assert dressed < plain * 1e4
    assert analyse("M0nk3y!").score <= 1


def test_leetspeak_is_undone():
    result = analyse("p@ssw0rd")
    assert [m.kind for m in result.matches] == ["dictionary"]
    assert "leet" in result.matches[0].detail


def test_reversed_words_are_found():
    assert analyse("drowssap").score == 0


def test_keyboard_walks():
    result = analyse("qazwsxedc")
    assert result.score == 0
    assert analyse("zaq12wsx").score <= 1
    assert (
        any(m.kind == "spatial" for m in analyse("poiuytrewq98").matches)
        or analyse("poiuytrewq98").score <= 1
    )


def test_sequences_and_repeats():
    assert any(m.kind == "sequence" for m in analyse("xxabcdefxx").matches)
    assert any(m.kind == "sequence" for m in analyse("97531").matches)
    assert any(m.kind == "repeat" for m in analyse("zq7zq7zq7").matches)
    assert analyse("zq7zq7zq7").guesses < analyse("zq7vr2kp9").guesses


@pytest.mark.parametrize(
    "password", ["15031987", "01/09/2002", "1-1-99", "20021230", "mia2015", "1999"]
)
def test_dates_and_years_are_cheap(password):  # type: ignore[no-untyped-def]
    assert analyse(password).score == 0


def test_context_words_are_the_first_guess():
    without = analyse("lucatessitore88").guesses
    with_context = analyse("lucatessitore88", ["Luca Tessitore"]).guesses
    assert with_context < without


def test_context_short_words_ignored():
    assert analyse("abcxyz9", ["ab"]).guesses == analyse("abcxyz9").guesses


def test_empty_and_whitespace():
    assert analyse("").score == 0
    assert analyse("   ").score == 0


def test_unicode_counts_as_a_big_alphabet():
    assert analyse("日本語のパスワード").guesses > analyse("abcdefghij".replace("a", "q")).guesses


def test_very_long_password_is_fast_and_strong():
    start = time.perf_counter()
    result = analyse("Zq8!" * 40 + "kT3#vNw9&xP2")
    assert time.perf_counter() - start < 3
    assert result.score == 4 and result.length == 172


def test_results_are_deterministic():
    assert analyse("Tr0ub4dor&3").guesses == analyse("Tr0ub4dor&3").guesses


def test_score_boundaries():
    def at(guesses: float) -> int:
        return sum(guesses >= limit for limit in estimate.SCORE_LIMITS)

    assert [at(1), at(1e6), at(1e9), at(1e12), at(1e16)] == [0, 1, 2, 3, 4]


@pytest.mark.parametrize(
    ("seconds", "text"),
    [
        (0.2, "instantly"),
        (1, "1 second"),
        (59, "59 seconds"),
        (120, "2 minutes"),
        (7200, "2 hours"),
        (86400 * 3, "3 days"),
        (86400 * 400, "1 year"),
        (1e12, "centuries"),
    ],
)
def test_humanise(seconds, text):  # type: ignore[no-untyped-def]
    assert humanise(seconds) == text


def test_crack_times_has_one_row_per_scenario_and_orders_by_speed():
    rows = crack_times(1e12)
    assert len(rows) == 4
    assert rows[-1][1] != rows[0][1]


def test_feedback_never_quotes_the_password():
    for password in ["qwerty123", "Summer2024!", "abcabcabc", "15031987"]:
        for tip in feedback(analyse(password), password):
            assert password not in tip
    assert any("most common" in t for t in feedback(analyse("password"), "password"))
    assert any("Keyboard" in t for t in feedback(analyse("plokijuhyg"), "plokijuhyg"))
    assert any("Dates" in t for t in feedback(analyse("15031987"), "15031987"))


def test_wordlist_extends_the_dictionary(tmp_path: Path):
    before = analyse("zorblaxquuxfrob").guesses
    path = tmp_path / "words.txt"
    path.write_text("first\r\nzorblaxquuxfrob\n\nthird\n", encoding="utf-8")
    try:
        assert load_wordlist(str(path)) >= 2
        assert analyse("zorblaxquuxfrob").guesses < before / 1e6
    finally:
        estimate._RANKS.pop("zorblaxquuxfrob", None)
        estimate._RANKS.pop("first", None)
        estimate._RANKS.pop("third", None)
        estimate._cached.cache_clear()


def test_keyboard_adjacency():
    assert QWERTY.direction("q", "w") >= 0
    assert QWERTY.direction("q", "a") >= 0
    assert QWERTY.direction("q", "p") == -1
    assert QWERTY.direction("a", "a") == -1
    assert QWERTY.base("Q") == "q" and QWERTY.base("!") == "1"
    assert QWERTY.is_shifted("!") and not QWERTY.is_shifted("1")
