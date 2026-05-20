# Contributing to SpecterScan

Thank you for wanting to improve SpecterScan. This project exists to protect buyers from hardware fraud, and every contribution counts.

---

## Ways to Contribute

### 1. Hardware Profiles

The most impactful contribution. Each profile lets SpecterScan compare a specific laptop's reported specs against known correct values.

**How to add a profile:**

1. Copy `profiles/custom_template.json`
2. Rename it: `profiles/<vendor>_<model>_<variant>.json` (e.g. `profiles/hp_elitebook_840_g10.json`)
3. Fill in all fields you can verify from official spec sheets
4. Link your sources in the `_sources` field
5. Open a pull request

**Good sources:**
- Official manufacturer spec page
- CPU-World, WikiChip (for CPU specs)
- NotebookCheck review (for battery capacity)
- User manual PDFs

### 2. Scam Pattern Documentation

Add newly discovered scam methods to `docs/known_scams.md`. Include:
- What the seller does to deceive
- How SpecterScan detects it (or a note if we don't yet)
- If possible, a detection improvement proposal

### 3. Code Improvements

**Before submitting code:**
- Run `python3 run.py --quick` and confirm no regressions
- Keep all modules import-free from third-party packages
- Follow the style conventions below
- Add docstrings to any new public functions

### 4. Bug Reports

Open an issue with:
- OS and Python version (`python3 --version`)
- The exact error message or unexpected behaviour
- Whether you ran with elevated privileges
- Sanitised scan output (remove serial numbers if sharing)

---

## Code Style

- **Python 3.6+ compatible** — no walrus operator, f-strings with `=` specifier, etc.
- **Type hints** on all function signatures
- **Docstrings** on all modules and public functions (Google style)
- **No global state** — pass data as function arguments
- **No bare `except`** — catch specific exceptions
- **`pathlib.Path`** for all file paths (never string concatenation)
- **Constants** at the top of each module, not inline magic values
- Run `python3 -m py_compile src/*.py` before submitting to check for syntax errors

---

## Pull Request Checklist

- [ ] No new third-party imports
- [ ] Works on Python 3.6+
- [ ] Gracefully handles missing tools/permissions
- [ ] Docstring on every new public function
- [ ] Code tested on at least one platform (Linux/macOS/Windows)

---

## License

By contributing, you agree your contributions are licensed under GPL v3.
