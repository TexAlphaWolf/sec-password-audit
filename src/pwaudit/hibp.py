"""Has this password appeared in a public breach, without telling anyone the password?

Have I Been Pwned's "Pwned Passwords" uses k-anonymity: you send the first 5 hex characters of the
SHA-1 of the password (1,048,576 possible prefixes, so each answer lists hundreds of suffixes
that all share yours), and compare the rest of the hash *locally*. The service never sees the
password or its full hash. SHA-1 is not a security choice here: it is the identifier the data set
is published under.

Two sources, same answer:
  * `RangeClient`: the online range API (`Add-Padding: true`, so response size does not leak
    how many suffixes matched).
  * `PwnedFile`: a downloaded "ordered by hash" file (hash:count lines), searched by binary search
    without loading it. No network at all.
"""

from __future__ import annotations

import hashlib
import os
import re
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO

DEFAULT_URL = "https://api.pwnedpasswords.com/range/"
_SUFFIX = re.compile(r"^[0-9A-F]{35}$")


class BreachError(Exception):
    """The check could not be made (network, bad file). Never means "not breached"."""


def sha1_hex(password: str) -> str:
    # The Pwned Passwords data set is keyed by SHA-1: this is an identifier, not password storage.
    return hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()


def split_hash(digest: str) -> tuple[str, str]:
    return digest[:5], digest[5:]


def parse_range(body: str) -> dict[str, int]:
    """`SUFFIX:COUNT` lines -> {suffix: count}. Padding entries (count 0) are dropped."""
    out: dict[str, int] = {}
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        suffix, sep, count = line.partition(":")
        suffix = suffix.upper()
        if not sep or not _SUFFIX.match(suffix) or not count.strip().isdigit():
            raise BreachError("the answer does not look like a Pwned Passwords range")
        if int(count) > 0:
            out[suffix] = int(count)
    return out


Fetch = Callable[[str, float], str]


def _fetch(url: str, timeout: float) -> str:
    request = urllib.request.Request(
        url, headers={"Add-Padding": "true", "User-Agent": "pwaudit", "Accept": "text/plain"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return str(response.read(8 * 1024 * 1024).decode("ascii", "replace"))
    except urllib.error.HTTPError as error:
        status = error.code
        error.close()
        raise BreachError(f"{url}: HTTP {status}") from error
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise BreachError(f"{url}: {type(error).__name__}") from error


class RangeClient:
    """Online lookup. Remembers each prefix it has asked, so a hundred passwords cost at most a
    hundred requests and the same prefix is never asked twice."""

    def __init__(
        self, url: str = DEFAULT_URL, timeout: float = 15.0, fetch: Fetch = _fetch
    ) -> None:
        self.url = url if url.endswith("/") else url + "/"
        self.timeout = timeout
        self._fetch = fetch
        self._cache: dict[str, dict[str, int]] = {}
        self.requests = 0

    def count(self, password: str) -> int:
        prefix, suffix = split_hash(sha1_hex(password))
        if prefix not in self._cache:
            self.requests += 1
            self._cache[prefix] = parse_range(self._fetch(self.url + prefix, self.timeout))
        return self._cache[prefix].get(suffix, 0)


class PwnedFile:
    """Offline lookup in a `hash:count` file sorted by hash (the "ordered by hash" download)."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        try:
            self._file: BinaryIO = open(self.path, "rb")  # noqa: SIM115 (closed in close())
        except OSError as error:
            raise BreachError(f"{path}: {error.strerror or error}") from error
        self._size = self.path.stat().st_size

    def close(self) -> None:
        self._file.close()

    def __enter__(self) -> PwnedFile:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _line_at(self, offset: int) -> tuple[int, bytes]:
        """The first complete line starting at or after `offset`: (its start, its text)."""
        self._file.seek(offset)
        if offset:
            self._file.seek(offset - 1)
            if self._file.read(1) != b"\n":
                self._file.readline()  # skip the rest of the line we landed in
        start = self._file.tell()
        return start, self._file.readline()

    def count(self, password: str) -> int:
        target = sha1_hex(password).encode("ascii")
        lo, hi = 0, self._size
        while lo < hi:
            mid = (lo + hi) // 2
            start, line = self._line_at(mid)
            if not line or start >= hi:
                hi = mid
                continue
            key, _, count = line.strip().partition(b":")
            if len(key) != 40:
                raise BreachError(f"{self.path}: not a hash:count file (found {line[:20]!r})")
            if key == target:
                return int(count) if count.isdigit() else 1
            if key < target:
                lo = start + len(line)
            else:
                hi = mid
        return 0


Checker = RangeClient | PwnedFile
