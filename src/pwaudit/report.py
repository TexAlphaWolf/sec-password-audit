"""Render an audit. Entries are named by label; passwords never appear."""

from __future__ import annotations

import json
import math

from .audit import Entry, Report

SCORE_NAMES = ("trivial", "weak", "fair", "strong", "very strong")


def _lines(report: Report) -> list[tuple[str, list[str]]]:
    sections: list[tuple[str, list[str]]] = []
    if report.empty:
        sections.append(("Empty password", [e.label for e in report.empty]))
    if report.breached:
        sections.append(
            (
                "Found in known breaches (change these first)",
                [f"{e.label}: seen {e.breached:,} times" for e in report.breached],
            )
        )
    if report.reused:
        sections.append(
            (
                "Reused (the same password on several entries)",
                [
                    f"{len(g)} entries share one password: " + "; ".join(e.label for e in g)
                    for g in report.reused
                ],
            )
        )
    if report.weak:
        sections.append(
            (
                f"Weak (score below {report.min_score}, {SCORE_NAMES[report.min_score]} or better wanted)",
                [
                    f"{e.label}: {SCORE_NAMES[e.score]}, about 2^{math.log2(max(e.guesses, 1.0)):.0f} guesses"
                    for e in report.weak
                ],
            )
        )
    shorter = [e for e in report.short if e not in report.weak]
    if shorter:
        sections.append(
            (
                f"Short (under {report.min_length} characters)",
                [f"{e.label}: {e.length} characters" for e in shorter],
            )
        )
    return sections


def _summary(report: Report) -> str:
    total = len(report.entries)
    text = f"{total} entries, {report.problems} with at least one problem"
    if not report.checked_breaches:
        text += " (breach check not run: add --hibp or --hibp-file)"
    elif report.breach_errors:
        text += f" ({report.breach_errors} breach lookups failed: those entries are NOT confirmed clean)"
    return text


def to_text(report: Report) -> str:
    out = [_summary(report), ""]
    for title, items in _lines(report):
        out.append(f"{title} - {len(items)}")
        out += [f"  {item}" for item in items]
        out.append("")
    if not _lines(report):
        out.append("Nothing to fix.")
    return "\n".join(out).rstrip() + "\n"


def to_markdown(report: Report) -> str:
    out = ["# Password audit", "", _summary(report), ""]
    for title, items in _lines(report):
        out += [f"## {title} ({len(items)})", ""]
        out += [f"- {item.replace('|', '/')}" for item in items]
        out.append("")
    if not _lines(report):
        out.append("Nothing to fix.")
    return "\n".join(out).rstrip() + "\n"


def _entry(e: Entry) -> dict[str, object]:
    return {
        "label": e.label,
        "score": e.score,
        "length": e.length,
        "breach_count": e.breached,
        "empty": e.empty,
    }


def to_json(report: Report) -> str:
    return json.dumps(
        {
            "entries": len(report.entries),
            "with_problems": report.problems,
            "breach_check": report.checked_breaches,
            "breach_lookup_errors": report.breach_errors,
            "empty": [_entry(e) for e in report.empty],
            "breached": [_entry(e) for e in report.breached],
            "reused": [[e.label for e in g] for g in report.reused],
            "weak": [_entry(e) for e in report.weak],
            "short": [_entry(e) for e in report.short],
        },
        indent=1,
    )
