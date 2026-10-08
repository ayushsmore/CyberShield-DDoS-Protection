from flask import Flask, render_template, jsonify, request
import sqlite3
from datetime import datetime

app = Flask(__name__)

DB = "ddos_guard.db"
DEFAULT_THRESHOLD = 100


def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS traffic_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            requests_per_sec INTEGER NOT NULL,
            status TEXT NOT NULL,
            action TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def current_stats():
    conn = get_db()

    rows = conn.execute("""
        SELECT requests_per_sec, status, action
        FROM traffic_logs
        ORDER BY id DESC
        LIMIT 100
    """).fetchall()

    conn.close()

    if not rows:
        return {
            "requests": 0,
            "normal": 0,
            "suspicious": 0,
            "blocked": 0,
            "threat_level": "LOW",
            "protection": "ACTIVE"
        }

    requests = sum(r["requests_per_sec"] for r in rows)
    suspicious = sum(
        1 for r in rows
        if r["status"] == "SUSPICIOUS"
    )

    blocked = sum(
        1 for r in rows
        if r["action"] == "RATE LIMIT"
    )

    if suspicious >= 5:
        threat = "HIGH"
    elif suspicious >= 2:
        threat = "MEDIUM"
    else:
        threat = "LOW"

    return {
        "requests": requests,
        "normal": len(rows) - suspicious,
        "suspicious": suspicious,
        "blocked": blocked,
        "threat_level": threat,
        "protection": "ACTIVE"
    }


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/traffic")
def traffic():
    return render_template("traffic.html")


@app.route("/alerts")
def alerts():
    return render_template("alerts.html")


@app.route("/logs")
def logs():
    return render_template("logs.html")


@app.route("/settings")
def settings():
    return render_template("settings.html")


@app.route("/api/stats")
def api_stats():
    return jsonify(current_stats())


@app.route("/api/logs")
def api_logs():
    conn = get_db()

    rows = conn.execute("""
        SELECT timestamp, requests_per_sec, status, action
        FROM traffic_logs
        ORDER BY id DESC
        LIMIT 50
    """).fetchall()

    conn.close()

    return jsonify([dict(row) for row in rows])


@app.post("/api/simulate")
def simulate():
    """
    Safe local demonstration endpoint.

    This creates a synthetic traffic observation
    instead of generating traffic against another system.
    """

    payload = request.get_json(silent=True) or {}

    rps = int(
        payload.get(
            "requests_per_sec",
            25
        )
    )

    threshold = int(
        payload.get(
            "threshold",
            DEFAULT_THRESHOLD
        )
    )

    suspicious = rps > threshold

    status = (
        "SUSPICIOUS"
        if suspicious
        else "NORMAL"
    )

    action = (
        "RATE LIMIT"
        if suspicious
        else "ALLOW"
    )

    conn = get_db()

    conn.execute("""
        INSERT INTO traffic_logs
        (
            timestamp,
            requests_per_sec,
            status,
            action
        )
        VALUES (?, ?, ?, ?)
    """, (
        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        rps,
        status,
        action
    ))

    conn.commit()
    conn.close()

    return jsonify({
        "status": status,
        "action": action,
        "requests_per_sec": rps
    })


# Initialize the database when the application starts.
# This is important for production servers such as Gunicorn.
init_db()


if __name__ == "__main__":
    app.run(debug=True)
