# 🛡️ Password Security Core

A real-time password strength checker built with Streamlit, styled as a dark,
high-tech HUD dashboard. Type or generate a password and get an instant
security breakdown: strength score, entropy, estimated crack time, a rule
checklist, and concrete suggestions for improvement.

## Features

- **Live strength analysis** — scores a password 0–6 based on length,
  uppercase, lowercase, digits, and special characters, then classifies it
  as Weak / Medium / Strong.
- **Entropy & crack-time estimate** — estimates bits of entropy from the
  character pool used and translates that into a human-readable "time to
  crack" (e.g. `3.0 hours`, `practically uncrackable`).
- **Breached-password check** — flags passwords that appear on common
  breached-password lists.
- **Secure key generator** — generates a cryptographically secure random
  password (via Python's `secrets` module) with a configurable length and
  character classes, loaded straight into the analyzer.
- **Session activity log** — a running, timestamped log of scans for the
  current session (strength and score only — raw passwords are never
  logged or stored).
- **JARVIS-style UI** — animated boot sequence, neon HUD theme, and
  glowing stat tiles, defined in `style.css`.

## Getting started

```bash
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt
python -m streamlit run app.py
```

The app opens at `http://localhost:8501`.

## Project structure

| File | Purpose |
|---|---|
| `app.py` | Streamlit UI — layout, widgets, and page logic. |
| `password_checker.py` | Core password-analysis logic (framework-independent, reusable/testable on its own). |
| `style.css` | HUD theme — colors, fonts, animations. |
| `.streamlit/config.toml` | Dark theme configuration for Streamlit's native widgets. |

## How strength is calculated

Each password earns up to 6 points: 1 point each for length ≥ 8 characters,
an uppercase letter, a lowercase letter, a number, and a special character,
plus a bonus point for 12+ characters.

| Score | Classification |
|---|---|
| 0 – 2 | 🔴 Weak |
| 3 – 4 | 🟡 Medium |
| 5 – 6 | 🟢 Strong |
