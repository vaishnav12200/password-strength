import os
from flask import Flask, jsonify, render_template, request
import sqlite3
from analyzer.password_checker import PasswordStrengthAnalyzer


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_DIR = os.path.join(BASE_DIR, "database")
DB_PATH = os.path.join(DB_DIR, "stats.db")


def get_db_connection():
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                strength_score INTEGER NOT NULL,
                password_length INTEGER NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


app = Flask(__name__, static_folder="static", template_folder="templates")
analyzer = PasswordStrengthAnalyzer()
init_db()


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    if password is None:
        password = ""

    result = analyzer.analyze(password)

    # Store ONLY statistics (never store actual passwords).
    if isinstance(result, dict) and "strength_score" in result:
        conn = get_db_connection()
        try:
            conn.execute(
                """
                INSERT INTO analyses (created_at, strength_score, password_length)
                VALUES (datetime('now'), ?, ?)
                """,
                (int(result["strength_score"]), int(result.get("length", 0))),
            )
            conn.commit()
        finally:
            conn.close()

    return jsonify(result)


@app.route("/history", methods=["GET"])
def history():
    conn = get_db_connection()
    try:
        total = conn.execute("SELECT COUNT(*) AS c FROM analyses").fetchone()["c"]
        avg = conn.execute("SELECT AVG(strength_score) AS a FROM analyses").fetchone()["a"]
        avg = 0 if avg is None else round(float(avg), 1)

        strong_count = conn.execute(
            "SELECT COUNT(*) AS c FROM analyses WHERE strength_score >= 80"
        ).fetchone()["c"]
        weak_count = conn.execute(
            "SELECT COUNT(*) AS c FROM analyses WHERE strength_score < 50"
        ).fetchone()["c"]

        return jsonify(
            {
                "total_analyses": int(total),
                "average_strength_score": avg,
                "strong_password_percentage": (float(strong_count) / float(total) * 100.0 if total else 0.0),
                "weak_password_percentage": (float(weak_count) / float(total) * 100.0 if total else 0.0),
            }
        )
    finally:
        conn.close()


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    # Production guidance: use gunicorn/uwsgi + proper env vars.
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
