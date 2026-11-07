#!/usr/bin/env python3
"""Does pwaudit still understand the REAL Pwned Passwords API? Needs internet. Exit 0 = yes.

The unit tests use a stand-in server. Only the prefix of a hash leaves this machine; the passwords
below are the two most famous ones in the data set plus a random one generated right now.

    python tools/live_check.py
"""

from __future__ import annotations

import secrets
import sys

from pwaudit.hibp import DEFAULT_URL, RangeClient, _fetch, parse_range, sha1_hex, split_hash

failures: list[str] = []


def check(ok: bool, text: str) -> None:
    print(("ok   " if ok else "FAIL ") + text)
    if not ok:
        failures.append(text)


def main() -> int:
    client = RangeClient()
    for famous in ("password", "123456"):
        count = client.count(famous)
        check(count > 1_000_000, f"'{famous}' is in the data set, seen {count:,} times")
    check(client.requests == 2, f"two passwords, two requests ({client.requests})")

    client.count("password")
    check(client.requests == 2, "the same prefix is not asked twice")

    unique = secrets.token_urlsafe(24)
    check(client.count(unique) == 0, "a random 32-character password is not in the data set")

    prefix, suffix = split_hash(sha1_hex("password"))
    body = _fetch(DEFAULT_URL + prefix, 15.0)
    parsed = parse_range(body)
    check(suffix in parsed, f"range {prefix} parses and contains the suffix of 'password'")
    check(
        len(parsed) > 100,
        f"the range lists {len(parsed)} suffixes sharing the prefix (hundreds expected)",
    )
    raw_lines = [line for line in body.splitlines() if line.strip()]
    check(
        len(raw_lines) >= len(parsed),
        f"padding entries present and ignored ({len(raw_lines) - len(parsed)} dropped)",
    )

    print(f"\n{len(failures)} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
