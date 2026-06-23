# Password Strength Analyzer

A cybersecurity-focused web application that evaluates password strength in real time, detects common weaknesses/patterns, estimates resistance to attacks, and provides improvement recommendations.

## Features
- Real-time password analysis (as you type)
- Password strength score (0–100) with progress bar
- Pattern detection (repeats, sequences, keyboard-like patterns, dictionary/common passwords, etc.)
- Attack estimation (Brute Force, Dictionary, Credential Stuffing)
- Detailed security report + recommendations
- Password entropy estimate (educational approximation)
- Responsive modern dark + blue security dashboard UI
- Optional SQLite history (stores only statistics — never stores passwords)
- Secure password generator (client-side only; never sent to server)

## Security Requirements (Important)
- Never log passwords
- Never save actual passwords
- Perform analysis locally in the backend without persisting the password
- Store only statistics in SQLite: timestamp, strength score, and password length

## Tech Stack
- Backend: Python 3, Flask
- Frontend: HTML5, CSS3, JavaScript
- Storage (optional): SQLite

## Setup Instructions

### 1) Create/Use a virtual environment (recommended)
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2) Install dependencies
```bash
pip install -r requirements.txt
```

### 3) Run the app
```bash
python app.py
```

Then open:
- http://127.0.0.1:5000/

## Endpoints
- `GET /` - Home page
- `POST /analyze` - Analyze password (request JSON: `{ "password": "..." }`)
- `GET /history` - Dashboard stats (aggregate only; no password data)

## Notes on Attack Time & Entropy
- Attack resistance and entropy are **educational approximations**, not guarantees.
- Real-world guessing difficulty depends on attacker resources, throttling, rate limits, and password policy.

## Project Structure
- `app.py`
- `analyzer/password_checker.py`
- `templates/index.html`
- `static/style.css`
- `static/script.js`
- `database/stats.db` (created automatically at runtime)
