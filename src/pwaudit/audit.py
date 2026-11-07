"""Audit a whole password-manager export: weak, reused, breached, empty. Never prints a password.

Passwords are looked at one row at a time; what is kept for the report is a label (the entry's
name and user name), a score, and a per-run keyed hash used only to see which entries share a
password. The key is random and thrown away with the process.
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import secrets
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from .estimate import analyse
from .hibp import BreachError, Checker

PASSWORD_COLUMNS = (
    "password",
    "login_password",
    "pass",
    "pwd",
    "passwort",
    "mot de passe",
    "contrasena",
)
NAME_COLUMNS = ("name", "title", "login_uri", "url", "site", "website", "origin", "web site")
USER_COLUMNS = ("username", "login_username", "user", "login", "email", "user name", "login name")
MAX_ROWS = 500_000


class AuditError(Exception):
    """The file cannot be audited (not a CSV, no password column)."""


@dataclass
class Entry:
    label: str
    score: int
    guesses: float
    length: int
    breached: int = 0  # times seen in breaches; 0 = not found (or not checked)
    empty: bool = False
    group: str = ""  # keyed hash: equal for equal passwords


@dataclass
class Report:
    entries: list[Entry] = field(default_factory=list)
    checked_breaches: bool = False
    breach_errors: int = 0
    min_score: int = 2
    min_length: int = 12

    @property
    def weak(self) -> list[Entry]:
        return [e for e in self.entries if not e.empty and e.score < self.min_score]

    @property
    def short(self) -> list[Entry]:
        return [e for e in self.entries if not e.empty and e.length < self.min_length]

    @property
    def breached(self) -> list[Entry]:
        return sorted((e for e in self.entries if e.breached), key=lambda e: -e.breached)

    @property
    def empty(self) -> list[Entry]:
        return [e for e in self.entries if e.empty]

    @property
    def reused(self) -> list[list[Entry]]:
        groups: dict[str, list[Entry]] = defaultdict(list)
        for e in self.entries:
            if not e.empty:
                groups[e.group].append(e)
        return sorted((g for g in groups.values() if len(g) > 1), key=lambda g: -len(g))

    @property
    def problems(self) -> int:
        flagged = {id(e) for e in self.weak + self.breached + self.empty}
        flagged |= {id(e) for g in self.reused for e in g}
        return len(flagged)


def _pick(header: list[str], candidates: tuple[str, ...]) -> int | None:
    lowered = [h.strip().lower() for h in header]
    for wanted in candidates:
        if wanted in lowered:
            return lowered.index(wanted)
    return None


def _cell(row: list[str], index: int | None) -> str:
    return row[index].strip() if index is not None and index < len(row) else ""


def read_rows(path: str | Path) -> Iterable[tuple[str, str, str]]:
    """(name, user, password) per row. Raises AuditError if there is no password column."""
    try:
        handle = open(path, encoding="utf-8-sig", newline="")  # noqa: SIM115
    except OSError as error:
        raise AuditError(f"{path}: {error.strerror or error}") from error
    with handle:
        # csv.Sniffer guesses the quoting too, and a wrong guess silently changes a password
        # (a stray quote left in it); only the delimiter is guessed, from the header line.
        first = handle.readline()
        handle.seek(0)
        delimiter = max(",;\t", key=lambda d: (first.count(d), d == ","))

        class Dialect(csv.excel):
            pass

        Dialect.delimiter = delimiter
        dialect = Dialect
        reader = csv.reader(handle, dialect)
        header = next(reader, None)
        if not header:
            raise AuditError(f"{path}: the file is empty")
        pw = _pick(header, PASSWORD_COLUMNS)
        if pw is None:
            raise AuditError(
                f"{path}: no password column (looked for: {', '.join(PASSWORD_COLUMNS[:3])}, ...). "
                f"Columns found: {', '.join(header[:8])}"
            )
        name, user = _pick(header, NAME_COLUMNS), _pick(header, USER_COLUMNS)
        for number, row in enumerate(reader, 1):
            if number > MAX_ROWS:
                raise AuditError(f"{path}: more than {MAX_ROWS:,} rows")
            if not any(cell.strip() for cell in row):
                continue
            yield _cell(row, name), _cell(row, user), _cell(row, pw)


def clean_label(name: str, user: str, row: int) -> str:
    raw = f"{name} ({user})" if user and name else user or name or f"row {row}"
    text = " ".join("".join(c if c.isprintable() else " " for c in raw).split())
    return text if len(text) <= 80 else text[:79] + "…"


def audit(
    rows: Iterable[tuple[str, str, str]],
    checker: Checker | None = None,
    min_score: int = 2,
    min_length: int = 12,
    key: bytes | None = None,
) -> Report:
    key = key or secrets.token_bytes(32)
    report = Report(
        checked_breaches=checker is not None, min_score=min_score, min_length=min_length
    )
    for number, (name, user, password) in enumerate(rows, 1):
        label = clean_label(name, user, number)
        if not password:
            report.entries.append(Entry(label, 0, 1.0, 0, empty=True))
            continue
        result = analyse(password, [name, user.split("@")[0]])
        entry = Entry(
            label,
            result.score,
            result.guesses,
            len(password),
            group=hmac.new(key, password.encode("utf-8"), hashlib.sha256).hexdigest(),
        )
        if checker is not None:
            try:
                entry.breached = checker.count(password)
            except BreachError:
                report.breach_errors += 1
        report.entries.append(entry)
    return report
