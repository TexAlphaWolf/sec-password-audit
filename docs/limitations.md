# Limitations

1. **It estimates typical cracking tools, not every attacker.** A targeted attacker who knows you (pet names, family dates) does better; `--context` models only the words you give it.
2. **The built-in dictionary is small** (about 1,000 passwords and words, English and Italian). A password made of a word it does not know is scored as random characters and its strength is **overestimated**. The calibration shows the estimator never exceeds the search space of truly random passwords; it says nothing about how many human-chosen words it recognises. Remedies: `--wordlist` with a large list (a leaked-password list you already have), and above all the breach check, which does not depend on guessing.
3. **Breach status needs the data.** Without `--hibp` or `--hibp-file` the result says *not checked*. A password absent from the data set is not necessarily safe, only not known to have leaked there.
4. **Keyboard layout.** Walk detection is for QWERTY. AZERTY, QWERTZ and non-Latin layouts will see fewer walks.
5. **Scores are relative to stated rates** (the four scenarios in the table). Real hash settings differ: a fast hash on better hardware, or a slow hash configured harder, shifts the real time.
6. **Passwords are not erased from memory** (Python strings are immutable).
7. **CSV only.** Password managers that export JSON or encrypted formats need converting to CSV first; the column names recognised are listed in `src/pwaudit/audit.py`.
8. **No fix advice per site**, no check of two-factor status, no check of the *username* against breaches.
