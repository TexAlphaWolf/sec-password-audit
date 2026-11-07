from __future__ import annotations

from pathlib import Path

import pytest

from pwaudit.audit import AuditError, audit, clean_label, read_rows
from pwaudit.hibp import BreachError
from pwaudit.report import to_json, to_markdown, to_text

PASSWORDS = ["Summer2024!", "hunter2", "xK9#mQ2$vL7@pR4", "tGv7!pQ#2zLk9wX"]


class FakeChecker:
    def __init__(self, found: dict[str, int], fail: set[str] | None = None) -> None:
        self.found, self.fail = found, fail or set()

    def count(self, password: str) -> int:
        if password in self.fail:
            raise BreachError("down")
        return self.found.get(password, 0)


def write(tmp_path: Path, text: str, name: str = "export.csv", encoding: str = "utf-8") -> Path:
    path = tmp_path / name
    path.write_bytes(text.encode(encoding))
    return path


CSV = """name,url,username,password
Bank,https://bank.example,luca@example.com,Summer2024!
Mail,https://mail.example,luca@example.com,Summer2024!
Forum,https://forum.example,luca,hunter2
Cloud,https://cloud.example,luca,xK9#mQ2$vL7@pR4
Wiki,https://wiki.example,luca,
"""


def test_finds_weak_reused_and_empty(tmp_path: Path):
    report = audit(read_rows(write(tmp_path, CSV)))
    assert len(report.entries) == 5
    assert [e.label for e in report.empty] == ["Wiki (luca)"]
    assert [[e.label for e in g] for g in report.reused] == [
        ["Bank (luca@example.com)", "Mail (luca@example.com)"]
    ]
    assert {e.label for e in report.weak} == {
        "Bank (luca@example.com)",
        "Mail (luca@example.com)",
        "Forum (luca)",
    }
    assert report.problems == 4
    assert not report.checked_breaches


def test_report_never_contains_a_password(tmp_path: Path):
    report = audit(read_rows(write(tmp_path, CSV)), FakeChecker({"hunter2": 17_000}))
    for text in (to_text(report), to_markdown(report), to_json(report)):
        for password in PASSWORDS:
            assert password not in text
    assert "17,000 times" in to_text(report)


def test_breaches_are_listed_most_seen_first(tmp_path: Path):
    csv = "name,password\na,one-password\nb,two-password\nc,three-password\n"
    report = audit(
        read_rows(write(tmp_path, csv)), FakeChecker({"one-password": 5, "three-password": 900})
    )
    assert [e.label for e in report.breached] == ["c", "a"]
    assert report.checked_breaches


def test_lookup_failures_are_counted_and_called_out(tmp_path: Path):
    csv = "name,password\na,aaa-bbb-ccc\nb,ddd-eee-fff\n"
    report = audit(read_rows(write(tmp_path, csv)), FakeChecker({}, fail={"aaa-bbb-ccc"}))
    assert report.breach_errors == 1
    assert "NOT confirmed clean" in to_text(report)


def test_context_makes_site_names_weak(tmp_path: Path):
    csv = "name,username,password\nexamplebank,luca,examplebank2020\n"
    with_context = audit(read_rows(write(tmp_path, csv)))
    assert with_context.entries[0].score <= 1


@pytest.mark.parametrize(
    ("header", "row"),
    [
        ("name,url,username,password", "A,https://a,u,pw123456789"),
        (
            "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp",
            ",,login,A,,,0,https://a,u,pw123456789,",
        ),
        ("Title;Login;Password;URL", "A;u;pw123456789;https://a"),
        ("Title\tPassword", "A\tpw123456789"),
        ("URL,Username,Password,Note", "https://a,u,pw123456789,"),
    ],
)
def test_common_export_layouts(tmp_path: Path, header, row):  # type: ignore[no-untyped-def]
    rows = list(read_rows(write(tmp_path, f"{header}\n{row}\n")))
    assert len(rows) == 1 and rows[0][2] == "pw123456789"


def test_bom_and_quotes_and_blank_lines(tmp_path: Path):
    text = '﻿name,username,password\n"A, Inc","u","pa,ss""word"\n\n,,\n'
    rows = list(read_rows(write(tmp_path, text)))
    assert rows == [("A, Inc", "u", 'pa,ss"word')]


def test_no_password_column(tmp_path: Path):
    with pytest.raises(AuditError, match="no password column"):
        list(read_rows(write(tmp_path, "a,b\n1,2\n")))
    with pytest.raises(AuditError, match="empty"):
        list(read_rows(write(tmp_path, "")))
    with pytest.raises(AuditError):
        list(read_rows(tmp_path / "missing.csv"))


def test_short_rows_do_not_crash(tmp_path: Path):
    rows = list(read_rows(write(tmp_path, "name,username,password\nA\nB,u\nC,u,pw\n")))
    assert [r[2] for r in rows] == ["", "", "pw"]


def test_labels_cannot_inject_terminal_codes():
    label = clean_label("evil\x1b[2J\x07site", "u\r\nser", 1)
    assert "\x1b" not in label and "\r" not in label and "\x07" not in label and "\n" not in label
    assert clean_label("", "", 7) == "row 7"
    assert len(clean_label("x" * 500, "", 1)) == 80


def test_reuse_uses_a_per_run_key(tmp_path: Path):
    rows = list(read_rows(write(tmp_path, CSV)))
    one = audit(rows, key=b"a" * 32)
    two = audit(rows, key=b"b" * 32)
    assert one.entries[0].group != two.entries[0].group
    assert one.entries[0].group == one.entries[1].group
    assert "Summer2024" not in one.entries[0].group


def test_clean_export_has_nothing_to_fix(tmp_path: Path):
    csv = "name,password\nA,tGv7!pQ#2zLk9wX\nB,vT8&nB3!kW5@dJ2#\n"
    report = audit(read_rows(write(tmp_path, csv)), FakeChecker({}))
    assert report.problems == 0
    assert "Nothing to fix" in to_text(report) and "Nothing to fix" in to_markdown(report)


def test_short_but_not_weak_is_listed_as_short(tmp_path: Path):
    csv = "name,password\nA,vT8&nB3!kW5\n"
    report = audit(read_rows(write(tmp_path, csv)))
    assert report.entries[0].length == 11 and report.entries[0] in report.short
    assert "Short" in to_text(report)
