from __future__ import annotations

import hashlib
import random
from pathlib import Path

import pytest

from pwaudit.hibp import BreachError, PwnedFile, RangeClient, parse_range, sha1_hex, split_hash

from .conftest import RangeServer


def test_sha1_known_vectors():
    assert sha1_hex("password") == "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
    assert sha1_hex("") == "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
    assert (
        sha1_hex("pässword")
        == hashlib.sha1("pässword".encode(), usedforsecurity=False).hexdigest().upper()
    )
    assert split_hash(sha1_hex("password")) == ("5BAA6", "1E4C9B93F3F0682250B6CF8331B7EE68FD8")


def test_parse_range_drops_padding_and_accepts_crlf():
    body = (
        "0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\r\n"
        + "A" * 35
        + ":0\r\n"
    )
    assert parse_range(body) == {
        "0018A45C4D1DEF81644B54AB7F969B88D65": 3,
        "00D4F6E8FA6EECAD2A3AA415EEC418D38EC": 2,
    }
    assert parse_range("") == {}


@pytest.mark.parametrize(
    "body",
    [
        "garbage",
        "ABC:1",
        "0018A45C4D1DEF81644B54AB7F969B88D65",
        "0018A45C4D1DEF81644B54AB7F969B88D65:x",
        "<html>blocked</html>",
    ],
)
def test_parse_range_rejects_what_is_not_a_range(body):  # type: ignore[no-untyped-def]
    with pytest.raises(BreachError):
        parse_range(body)


def test_range_client_sends_only_the_prefix_and_asks_for_padding(pwned: RangeServer):
    pwned.add("password", 9_545_824)
    client = RangeClient(pwned.base)
    assert client.count("password") == 9_545_824
    assert client.count("a-password-nobody-used-9f3k") == 0
    paths = [p for p, _ in pwned.requests]
    assert paths[0].endswith("/5BAA6")
    assert all(len(p.rsplit("/", 1)[-1]) == 5 for p in paths)
    assert all("password" not in p.lower() for p in paths)
    assert all(padding == "true" for _, padding in pwned.requests)


def test_range_client_asks_each_prefix_once(pwned: RangeServer):
    pwned.add("password", 5)
    client = RangeClient(pwned.base)
    for _ in range(5):
        client.count("password")
    assert client.requests == 1


def test_range_client_errors_are_never_a_clean_result(pwned: RangeServer):
    pwned.status = 503
    with pytest.raises(BreachError, match="503"):
        RangeClient(pwned.base).count("anything")
    with pytest.raises(BreachError):
        RangeClient("http://127.0.0.1:1/range/", timeout=1).count("anything")


def test_range_client_trailing_slash_is_optional(pwned: RangeServer):
    pwned.add("password", 1)
    assert RangeClient(pwned.base.rstrip("/")).count("password") == 1


def _write_sorted(
    path: Path, passwords: dict[str, int], noise: int, newline: str = "\n", seed: int = 1
) -> None:
    rng = random.Random(seed)
    rows = {sha1_hex(p): c for p, c in passwords.items()}
    for _ in range(noise):
        rows[hashlib.sha1(rng.randbytes(8), usedforsecurity=False).hexdigest().upper()] = (
            rng.randrange(1, 500)
        )
    path.write_bytes(
        newline.join(f"{h}:{c}" for h, c in sorted(rows.items())).encode() + newline.encode()
    )


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_pwned_file_finds_everything_it_holds(tmp_path: Path, newline: str):
    known = {f"known-{i}": i + 1 for i in range(50)}
    path = tmp_path / "pwned.txt"
    _write_sorted(path, known, 3000, newline)
    with PwnedFile(path) as db:
        for password, count in known.items():
            assert db.count(password) == count
        assert db.count("never-in-the-file") == 0
        assert db.count("") == 0


def test_pwned_file_first_and_last_lines_and_tiny_files(tmp_path: Path):
    path = tmp_path / "pwned.txt"
    known = {f"p{i}": i + 1 for i in range(200)}
    _write_sorted(path, known, 0)
    ordered = sorted(known, key=sha1_hex)  # the first and the last line of the file are in here
    with PwnedFile(path) as db:
        assert db.count(ordered[0]) == known[ordered[0]]
        assert db.count(ordered[-1]) == known[ordered[-1]]
        assert all(db.count(p) == c for p, c in known.items())
    one = tmp_path / "one.txt"
    _write_sorted(one, {"only": 7}, 0)
    with PwnedFile(one) as db:
        assert db.count("only") == 7 and db.count("other") == 0
    two = tmp_path / "two.txt"
    _write_sorted(two, {"a": 1, "b": 2}, 0)
    with PwnedFile(two) as db:
        assert (db.count("a"), db.count("b"), db.count("c")) == (1, 2, 0)


def test_pwned_file_no_trailing_newline(tmp_path: Path):
    path = tmp_path / "p.txt"
    _write_sorted(path, {"x": 3, "y": 4}, 100)
    path.write_bytes(path.read_bytes().rstrip(b"\n"))
    with PwnedFile(path) as db:
        assert db.count("x") == 3 and db.count("y") == 4


def test_pwned_file_empty(tmp_path: Path):
    path = tmp_path / "empty.txt"
    path.write_bytes(b"")
    with PwnedFile(path) as db:
        assert db.count("anything") == 0


def test_pwned_file_not_a_hash_file(tmp_path: Path):
    path = tmp_path / "bad.txt"
    path.write_text("this is not a hash file\nat all\n")
    with PwnedFile(path) as db, pytest.raises(BreachError, match="not a hash:count"):
        db.count("x")


def test_pwned_file_missing(tmp_path: Path):
    with pytest.raises(BreachError):
        PwnedFile(tmp_path / "nope.txt")
