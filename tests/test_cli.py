from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from pwaudit import cli
from pwaudit.hibp import sha1_hex

from .conftest import RangeServer

SECRET = "xK9#mQ2$vL7@pR4"


def run(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, *argv: str, stdin: str = ""
) -> tuple[int, str, str]:
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    code = cli.main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_version(capsys: pytest.CaptureFixture[str]):
    with pytest.raises(SystemExit) as stop:
        cli.main(["--version"])
    assert stop.value.code == 0 and "pwaudit" in capsys.readouterr().out


def test_check_weak(capsys, monkeypatch):  # type: ignore[no-untyped-def]
    code, out, _ = run(capsys, monkeypatch, "check", "--exit-code", stdin="hunter2\n")
    assert code == 3
    assert "trivial" in out and "not checked" in out and "hunter2" not in out


def test_check_strong_and_json(capsys, monkeypatch):  # type: ignore[no-untyped-def]
    code, out, _ = run(capsys, monkeypatch, "check", "--json", "--exit-code", stdin=SECRET + "\r\n")
    data = json.loads(out)
    assert code == 0 and data["ok"] and data["score"] == 4 and data["length"] == len(SECRET)
    assert data["breach_count"] is None and len(data["crack_times"]) == 4
    assert SECRET not in out


def test_the_password_is_never_an_argument(capsys, monkeypatch):  # type: ignore[no-untyped-def]
    with pytest.raises(SystemExit) as stop:
        run(capsys, monkeypatch, "check", "hunter2")
    assert stop.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err


def test_empty_password(capsys, monkeypatch):  # type: ignore[no-untyped-def]
    code, _, err = run(capsys, monkeypatch, "check", stdin="\n")
    assert code == 2 and "empty" in err


def test_check_against_hibp(capsys, monkeypatch, pwned: RangeServer):  # type: ignore[no-untyped-def]
    pwned.add(SECRET, 42)
    code, out, _ = run(
        capsys,
        monkeypatch,
        "check",
        "--hibp",
        "--hibp-url",
        pwned.base,
        "--exit-code",
        stdin=SECRET + "\n",
    )
    assert code == 3 and "FOUND 42 times" in out
    assert len(pwned.requests) == 1
    assert pwned.requests[0][0].endswith("/" + sha1_hex(SECRET)[:5])
    assert sha1_hex(SECRET)[5:] not in pwned.requests[0][0]


def test_check_not_found_in_hibp(capsys, monkeypatch, pwned: RangeServer):  # type: ignore[no-untyped-def]
    code, out, _ = run(
        capsys,
        monkeypatch,
        "check",
        "--hibp",
        "--hibp-url",
        pwned.base,
        "--json",
        stdin=SECRET + "\n",
    )
    assert code == 0 and json.loads(out)["breach_count"] == 0


def test_hibp_failure_is_not_reported_as_clean(capsys, monkeypatch, pwned: RangeServer):  # type: ignore[no-untyped-def]
    pwned.status = 500
    code, out, _ = run(
        capsys, monkeypatch, "check", "--hibp", "--hibp-url", pwned.base, stdin=SECRET + "\n"
    )
    assert code == 1 and "NOT a clean result" in out and "not found" not in out


def test_check_with_offline_file(capsys, monkeypatch, tmp_path: Path):  # type: ignore[no-untyped-def]
    path = tmp_path / "pwned.txt"
    path.write_text("\n".join(sorted([f"{sha1_hex(SECRET)}:7", f"{sha1_hex('other')}:1"])) + "\n")
    code, out, _ = run(capsys, monkeypatch, "check", "--hibp-file", str(path), stdin=SECRET + "\n")
    assert "FOUND 7 times" in out and code == 0
    code, out, _ = run(
        capsys, monkeypatch, "check", "--hibp-file", str(path), stdin="a-different-password-1\n"
    )
    assert "not found in the data set" in out


def test_missing_hibp_file(capsys, monkeypatch, tmp_path: Path):  # type: ignore[no-untyped-def]
    code, _, err = run(
        capsys, monkeypatch, "check", "--hibp-file", str(tmp_path / "no.txt"), stdin="x\n"
    )
    assert code == 2 and "pwaudit:" in err


def test_context_flag(capsys, monkeypatch):  # type: ignore[no-untyped-def]
    _, plain, _ = run(capsys, monkeypatch, "check", "--json", stdin="lucatessitore88\n")
    _, context, _ = run(
        capsys,
        monkeypatch,
        "check",
        "--json",
        "--context",
        "Luca Tessitore",
        stdin="lucatessitore88\n",
    )
    assert json.loads(context)["bits"] < json.loads(plain)["bits"]


def test_min_score_and_length_are_adjustable(capsys, monkeypatch):  # type: ignore[no-untyped-def]
    code, _, _ = run(
        capsys,
        monkeypatch,
        "check",
        "--exit-code",
        "--min-length",
        "8",
        "--min-score",
        "0",
        stdin="xK9#mQ2$\n",
    )
    assert code == 0
    code, _, _ = run(
        capsys, monkeypatch, "check", "--exit-code", "--min-length", "20", stdin=SECRET + "\n"
    )
    assert code == 3


def test_wordlist_option(capsys, monkeypatch, tmp_path: Path):  # type: ignore[no-untyped-def]
    from pwaudit import estimate

    words = tmp_path / "w.txt"
    words.write_text("blorptastic-unique-zz\n")
    try:
        _, base, _ = run(capsys, monkeypatch, "check", "--json", stdin="blorptastic-unique-zz\n")
        _, with_list, _ = run(
            capsys,
            monkeypatch,
            "check",
            "--json",
            "--wordlist",
            str(words),
            stdin="blorptastic-unique-zz\n",
        )
        assert json.loads(with_list)["bits"] < json.loads(base)["bits"]
    finally:
        estimate._RANKS.pop("blorptastic-unique-zz", None)
        estimate._cached.cache_clear()


CSV = "name,username,password\nBank,luca,Summer2024!\nMail,luca,Summer2024!\nCloud,luca,xK9#mQ2$vL7@pR4\n"


def test_audit_formats_and_exit_codes(capsys, monkeypatch, tmp_path: Path):  # type: ignore[no-untyped-def]
    path = tmp_path / "e.csv"
    path.write_text(CSV)
    code, out, _ = run(capsys, monkeypatch, "audit", str(path), "--exit-code")
    assert code == 3 and "Reused" in out and "Summer2024!" not in out
    code, out, _ = run(capsys, monkeypatch, "audit", str(path), "--format", "md")
    assert code == 0 and out.startswith("# Password audit")
    code, out, _ = run(capsys, monkeypatch, "audit", str(path), "--format", "json")
    data = json.loads(out)
    assert data["entries"] == 3 and len(data["reused"]) == 1 and "Summer2024!" not in out


def test_audit_with_hibp(capsys, monkeypatch, tmp_path: Path, pwned: RangeServer):  # type: ignore[no-untyped-def]
    path = tmp_path / "e.csv"
    path.write_text(CSV)
    pwned.add("Summer2024!", 1234)
    _, out, _ = run(capsys, monkeypatch, "audit", str(path), "--hibp", "--hibp-url", pwned.base)
    assert "seen 1,234 times" in out and "breach check not run" not in out
    assert len(pwned.requests) == 2  # two distinct passwords, two prefixes: never one per row


def test_audit_errors(capsys, monkeypatch, tmp_path: Path):  # type: ignore[no-untyped-def]
    bad = tmp_path / "bad.csv"
    bad.write_text("a,b\n1,2\n")
    code, _, err = run(capsys, monkeypatch, "audit", str(bad))
    assert code == 2 and "no password column" in err
    code, _, err = run(capsys, monkeypatch, "audit", str(tmp_path / "none.csv"))
    assert code == 2


def test_runs_as_a_real_process_reading_a_pipe():
    """End to end through `python -m pwaudit`, the way a shell pipe would use it."""
    import subprocess
    import sys

    done = subprocess.run(
        [sys.executable, "-m", "pwaudit", "check", "--json"],
        input=SECRET + "\n",
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout)["score"] == 4
    assert SECRET not in done.stdout + done.stderr
