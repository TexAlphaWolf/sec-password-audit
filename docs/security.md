# Security notes

A tool that handles passwords has to be careful with them. The rules it follows:

## What it does with a password

- **Input only from the keyboard (hidden) or a pipe.** There is no argument that takes a password: it would end up in shell history and in the process list (`ps`). `test_the_password_is_never_an_argument` checks that passing one is an error.
- **Never printed, never logged.** Advice text is generated from the *kind* of pattern found (never quoting it); reports name entries by label. Tests assert that no password appears in the text, Markdown or JSON output, nor in any advice sentence.
- **Nothing is written to disk.** No cache, no history file, no temporary file. The only file written is the report you redirect yourself.
- **Reuse detection uses a per-run keyed hash** (HMAC-SHA-256 with a random 32-byte key that exists only in that process). Equal passwords give equal tags within a run; the tags are meaningless afterwards and cannot be compared across runs.

## What leaves the machine (only with `--hibp`)

The first **5 hex characters of the SHA-1** of the password, to `api.pwnedpasswords.com`, in the URL path. That is 1 of 1,048,576 prefixes, shared by hundreds of unrelated passwords; the service cannot tell which one you hold. The request carries `Add-Padding: true`, so the response length does not reveal how many suffixes matched. The comparison happens locally. Each distinct prefix is requested once per run.

SHA-1 is **not a security choice** here: it is the identifier the data set is published under. `--hibp-file` needs no network at all.

A failed lookup (network, HTTP error, a response that is not a range) is reported as *not checked* with exit code 1. It is never turned into "not found".

## Inputs treated as hostile

- **CSV exports.** Only the delimiter is guessed (from the header line); quoting is always standard, because guessing quoting can silently change a password. Row count and file are bounded; labels are stripped of control characters before they reach a terminal (`test_labels_cannot_inject_terminal_codes`).
- **The breach file.** A file that is not `hash:count` lines raises an error instead of being searched with garbage.
- **The API answer.** Parsed strictly; anything that is not `35 hex characters:count` is rejected.

## What it cannot protect against

- A compromised machine (keylogger, malware) sees the password as you type it.
- Python strings are immutable: the password stays in memory until the garbage collector reuses it. Do not use the tool on a shared or untrusted computer.
- A password manager export is plain text. Create it on a trusted machine, run the audit, delete it (securely if your system supports that).

## Reporting

See [SECURITY.md](../SECURITY.md).
