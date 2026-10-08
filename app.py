from flask import Flask, render_template, jsonify, request, make_response
import sqlite3
import time
from collections import defaultdict, deque
from datetime import datetime

app = Flask(__name__)

DB = "ddos_guard.db"

# ==============================
# CYBERSHIELD CONFIGURATION
# ==============================

REQUEST_THRESHOLD = 20       # requests per second per client
WINDOW_SECONDS = 1

# In-memory request tracker
request_tracker = defaultdict(deque)


# ==============================
# DATABASE
# ==============================

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    # Existing demo table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS traffic_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            requests_per_sec INTEGER NOT NULL,
            status TEXT NOT NULL,
            action TEXT NOT NULL
        )
    """)

    # REAL request tracking table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS request_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            requests_per_sec INTEGER NOT NULL,
            status TEXT NOT NULL,
            action TEXT NOT NULL,
            response_code INTEGER NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# ==============================
# REAL REQUEST TRACKER
# ==============================

def get_client_ip():
    """
    Get the client IP address.

    For local testing, request.remote_addr is used.
    Later, when CyberShield is placed behind a trusted
    reverse proxy, we will configure trusted proxy headers.
    """
    return request.remote_addr or "unknown"


def check_request_rate(client_ip):
    """
    Track requests from one client during a rolling
    one-second window.
    """

    now = time.time()

    timestamps = request_tracker[client_ip]

    # Remove requests older than one second
    while timestamps and timestamps[0] <= now - WINDOW_SECONDS:
        timestamps.popleft()

    # Record current request
    timestamps.append(now)

    current_rate = len(timestamps)

    return current_rate


def log_real_request(
    client_ip,
    method,
    path,
    requests_per_sec,
    status,
    action,
    response_code
):
    conn = get_db()

    conn.execute("""
        INSERT INTO request_events
        (
            timestamp,
            client_ip,
            method,
            path,
            requests_per_sec,
            status,
            action,
            response_code
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        client_ip,
        method,
        path,
        requests_per_sec,
        status,
        action,
        response_code
    ))

    conn.commit()
    conn.close()


# ==============================
# CYBERSHIELD PROTECTION ENGINE
# ==============================

@app.before_request
def cyber_shield_protection():

    # Do not monitor static files.
    if request.path.startswith("/static/"):
        return None

    # Dashboard/control endpoints are not the protected website.
    # The /protected endpoint represents the customer website
    # we are protecting.
    if not request.path.startswith("/protected"):
        return None

    client_ip = get_client_ip()

    current_rate = check_request_rate(client_ip)

    # ==========================
    # NORMAL REQUEST
    # ==========================

    if current_rate <= REQUEST_THRESHOLD:

        log_real_request(
            client_ip=client_ip,
            method=request.method,
            path=request.path,
            requests_per_sec=current_rate,
            status="NORMAL",
            action="ALLOW",
            response_code=200
        )

        return None

    # ==========================
    # SUSPICIOUS REQUEST
    # ==========================

    log_real_request(
        client_ip=client_ip,
        method=request.method,
        path=request.path,
        requests_per_sec=current_rate,
        status="SUSPICIOUS",
        action="RATE LIMIT",
        response_code=429
    )

    response = make_response(
        jsonify({
            "error": "Too Many Requests",
            "message": "CyberShield rate limit exceeded.",
            "requests_per_second": current_rate,
            "threshold": REQUEST_THRESHOLD
        }),
        429
    )

    response.headers["Retry-After"] = "1"

    return response


# ==============================
# DASHBOARD PAGES
# ==============================

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


# ==============================
# PROTECTED DEMO WEBSITE
# ==============================

@app.route("/protected")
def protected_website():

    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Protected Website</title>

        <style>
            body {
                margin: 0;
                font-family: Arial, sans-serif;
                background: #071018;
                color: white;
                display: flex;
                align-items: center;
                justify-content: center;
                min-height: 100vh;
            }

            .card {
                width: 600px;
                padding: 45px;
                border-radius: 20px;
                background: #111c2b;
                border: 1px solid #1f9bc4;
                box-shadow: 0 0 40px rgba(0, 200, 255, 0.15);
                text-align: center;
            }

            h1 {
                color: #61dafb;
            }

            .status {
                margin-top: 20px;
                padding: 15px;
                border-radius: 10px;
                background: #10291e;
                color: #52ff9a;
            }

            p {
                color: #9fb2c8;
            }
        </style>
    </head>

    <body>

        <div class="card">

            <h1>🛡️ Protected Website</h1>

            <p>
                This website is protected by CyberShield.
            </p>

            <div class="status">
                ● CyberShield Protection Active
            </div>

            <p>
                Every request to this page is monitored
                by the CyberShield request protection engine.
            </p>

        </div>

    </body>
    </html>
    """


# ==============================
# REAL REQUEST LOG API
# ==============================

@app.route("/api/real-logs")
def real_logs():

    conn = get_db()

    rows = conn.execute("""
        SELECT
            timestamp,
            client_ip,
            method,
            path,
            requests_per_sec,
            status,
            action,
            response_code
        FROM request_events
        ORDER BY id DESC
        LIMIT 100
    """).fetchall()

    conn.close()

    return jsonify([dict(row) for row in rows])


# ==============================
# REAL REQUEST STATISTICS
# ==============================

@app.route("/api/real-stats")
def real_stats():

    conn = get_db()

    total = conn.execute("""
        SELECT COUNT(*) AS count
        FROM request_events
    """).fetchone()["count"]

    normal = conn.execute("""
        SELECT COUNT(*) AS count
        FROM request_events
        WHERE status = 'NORMAL'
    """).fetchone()["count"]

    suspicious = conn.execute("""
        SELECT COUNT(*) AS count
        FROM request_events
        WHERE status = 'SUSPICIOUS'
    """).fetchone()["count"]

    rate_limited = conn.execute("""
        SELECT COUNT(*) AS count
        FROM request_events
        WHERE action = 'RATE LIMIT'
    """).fetchone()["count"]

    conn.close()

    if suspicious >= 10:
        threat = "HIGH"
    elif suspicious >= 3:
        threat = "MEDIUM"
    else:
        threat = "LOW"

    return jsonify({
        "total_requests": total,
        "normal_requests": normal,
        "suspicious_requests": suspicious,
        "rate_limited": rate_limited,
        "threat_level": threat
    })


# ==============================
# OLD DEMO ENDPOINT
# ==============================

@app.route("/api/stats")
def api_stats():

    conn = get_db()

    rows = conn.execute("""
        SELECT requests_per_sec, status, action
        FROM traffic_logs
        ORDER BY id DESC
        LIMIT 100
    """).fetchall()

    conn.close()

    if not rows:
        return jsonify({
            "requests": 0,
            "normal": 0,
            "suspicious": 0,
            "blocked": 0,
            "threat_level": "LOW",
            "protection": "ACTIVE"
        })

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

    return jsonify({
        "requests": requests,
        "normal": len(rows) - suspicious,
        "suspicious": suspicious,
        "blocked": blocked,
        "threat_level": threat,
        "protection": "ACTIVE"
    })


# ==============================
# STARTUP
# ==============================

init_db()


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
