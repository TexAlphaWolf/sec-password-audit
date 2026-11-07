# Contributing

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
ruff check . && ruff format --check . && mypy && pytest --cov
python tools/evaluate.py --n 2000 --seed 7
python tools/live_check.py                         # the real API (needs internet)
```

- Standard library only for the package.
- **Nothing that prints, logs or stores a password.** A new output path needs a test that feeds it a password and asserts the password is absent.
- A change to the estimator must keep `tools/evaluate.py` reporting **0 estimates above the true search space**; CI fails otherwise. Add a test row for the pattern it fixes.
- A change to the breach lookup keeps "failed lookup is never a clean result".
