import os
import sqlite3
import time
from collections import defaultdict, deque
from functools import wraps
from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    session
)

app = Flask(__name__)

# ============================================================
# CONFIGURATION
# ============================================================

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "CyberShield-Secret-Key-2026"
)

ADMIN_USERNAME = os.environ.get(
    "ADMIN_USERNAME",
    "admin"
)

ADMIN_PASSWORD = os.environ.get(
    "ADMIN_PASSWORD",
    "CyberShield@2026"
)

DATABASE = "cybershield.db"

DEFAULT_THRESHOLD = 20
WINDOW_SECONDS = 1
ATTACK_ACTIVE_SECONDS = 10

# In-memory request tracker
request_tracker = defaultdict(deque)

# Runtime threshold
REQUEST_THRESHOLD = DEFAULT_THRESHOLD


# ============================================================
# DATABASE
# ============================================================

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
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

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            action TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attack_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attack_type TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            peak_rate INTEGER NOT NULL,
            suspicious_requests INTEGER NOT NULL,
            blocked_requests INTEGER NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY,
            request_threshold INTEGER NOT NULL
        )
    """)

    cursor.execute("""
        INSERT OR IGNORE INTO settings
        (id, request_threshold)
        VALUES (1, ?)
    """, (DEFAULT_THRESHOLD,))

    conn.commit()
    conn.close()


init_db()


# ============================================================
# SETTINGS
# ============================================================

def get_threshold():

    global REQUEST_THRESHOLD

    conn = get_db()

    row = conn.execute("""
        SELECT request_threshold
        FROM settings
        WHERE id = 1
    """).fetchone()

    conn.close()

    if row:
        REQUEST_THRESHOLD = int(row["request_threshold"])

    return REQUEST_THRESHOLD


def set_threshold(value):

    global REQUEST_THRESHOLD

    value = int(value)

    if value < 1:
        value = 1

    if value > 10000:
        value = 10000

    conn = get_db()

    conn.execute("""
        UPDATE settings
        SET request_threshold = ?
        WHERE id = 1
    """, (value,))

    conn.commit()
    conn.close()

    REQUEST_THRESHOLD = value

    return value


get_threshold()


# ============================================================
# AUTHENTICATION
# ============================================================

def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if not session.get("logged_in"):
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return wrapper


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if (
            username == ADMIN_USERNAME
            and password == ADMIN_PASSWORD
        ):

            session["logged_in"] = True
            session["username"] = username

            return redirect(url_for("dashboard"))

        return render_template(
            "login.html",
            error="Invalid username or password"
        )

    return render_template("login.html")


@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# ============================================================
# CLIENT IP
# ============================================================

def get_client_ip():

    forwarded_for = request.headers.get(
        "X-Forwarded-For"
    )

    if forwarded_for:

        return forwarded_for.split(",")[0].strip()

    return request.remote_addr or "unknown"


# ============================================================
# REQUEST TRACKING
# ============================================================

def get_request_rate(client_ip):

    now = time.time()

    requests = request_tracker[client_ip]

    requests.append(now)

    while requests and requests[0] < now - WINDOW_SECONDS:
        requests.popleft()

    return len(requests)


# ============================================================
# ALERT CREATION
# ============================================================

def create_alert(
    client_ip,
    requests_per_sec,
    action
):

    conn = get_db()

    severity = "HIGH"

    if requests_per_sec >= 100:
        severity = "CRITICAL"

    message = (
        f"Suspicious request rate detected: "
        f"{requests_per_sec} requests/sec"
    )

    conn.execute("""
        INSERT INTO alerts (
            timestamp,
            client_ip,
            alert_type,
            severity,
            message,
            action
        )
        VALUES (
            datetime('now'),
            ?,
            ?,
            ?,
            ?,
            ?
        )
    """, (
        client_ip,
        "HTTP Flood",
        severity,
        message,
        action
    ))

    conn.commit()
    conn.close()


# ============================================================
# ATTACK TRACKER
# ============================================================

def track_attack(
    client_ip,
    requests_per_sec
):

    if requests_per_sec <= REQUEST_THRESHOLD:
        return

    conn = get_db()

    active_attack = conn.execute("""
        SELECT *
        FROM attack_events
        WHERE source_ip = ?
        AND status = 'ACTIVE'
        ORDER BY id DESC
        LIMIT 1
    """, (client_ip,)).fetchone()

    now = time.strftime(
        "%Y-%m-%d %H:%M:%S",
        time.gmtime()
    )

    severity = "HIGH"

    if requests_per_sec >= 100:
        severity = "CRITICAL"

    if active_attack:

        peak_rate = max(
            active_attack["peak_rate"],
            requests_per_sec
        )

        suspicious_requests = (
            active_attack["suspicious_requests"] + 1
        )

        blocked_requests = (
            active_attack["blocked_requests"] + 1
        )

        conn.execute("""
            UPDATE attack_events

            SET
                last_seen = ?,
                peak_rate = ?,
                suspicious_requests = ?,
                blocked_requests = ?,
                severity = ?

            WHERE id = ?
        """, (
            now,
            peak_rate,
            suspicious_requests,
            blocked_requests,
            severity,
            active_attack["id"]
        ))

    else:

        conn.execute("""
            INSERT INTO attack_events (
                attack_type,
                source_ip,
                first_seen,
                last_seen,
                peak_rate,
                suspicious_requests,
                blocked_requests,
                severity,
                status
            )

            VALUES (
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?
            )
        """, (
            "HTTP Flood",
            client_ip,
            now,
            now,
            requests_per_sec,
            1,
            1,
            severity,
            "ACTIVE"
        ))

    conn.commit()
    conn.close()


# ============================================================
# ATTACK STATUS REFRESH
# ============================================================

def refresh_attack_status():

    conn = get_db()

    attacks = conn.execute("""
        SELECT id, last_seen
        FROM attack_events
        WHERE status = 'ACTIVE'
    """).fetchall()

    now = time.time()

    for attack in attacks:

        try:

            attack_time = time.mktime(
                time.strptime(
                    attack["last_seen"],
                    "%Y-%m-%d %H:%M:%S"
                )
            )

            if now - attack_time > ATTACK_ACTIVE_SECONDS:

                conn.execute("""
                    UPDATE attack_events
                    SET status = 'MITIGATED'
                    WHERE id = ?
                """, (attack["id"],))

        except Exception:
            pass

    conn.commit()
    conn.close()


# ============================================================
# REQUEST PROTECTION ENGINE
# ============================================================

@app.before_request
def protection_engine():

    # Don't interfere with login/static/API navigation
    ignored_paths = [
        "/login",
        "/logout",
        "/static"
    ]

    for ignored in ignored_paths:

        if request.path.startswith(ignored):
            return None

    client_ip = get_client_ip()

    requests_per_sec = get_request_rate(
        client_ip
    )

    # Only protect the demo protected website
    if request.path.startswith("/protected"):

        if requests_per_sec > get_threshold():

            track_attack(
                client_ip,
                requests_per_sec
            )

            create_alert(
                client_ip,
                requests_per_sec,
                "RATE LIMIT"
            )

            conn = get_db()

            conn.execute("""
                INSERT INTO request_events (
                    timestamp,
                    client_ip,
                    method,
                    path,
                    requests_per_sec,
                    status,
                    action,
                    response_code
                )

                VALUES (
                    datetime('now'),
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?
                )
            """, (
                client_ip,
                request.method,
                request.path,
                requests_per_sec,
                "SUSPICIOUS",
                "RATE LIMIT",
                429
            ))

            conn.commit()
            conn.close()

            response = jsonify({
                "status": "blocked",
                "message": "Too many requests",
                "requests_per_second": requests_per_sec,
                "threshold": get_threshold()
            })

            response.status_code = 429
            response.headers["Retry-After"] = "1"

            return response

    # Log normal request
    conn = get_db()

    conn.execute("""
        INSERT INTO request_events (
            timestamp,
            client_ip,
            method,
            path,
            requests_per_sec,
            status,
            action,
            response_code
        )

        VALUES (
            datetime('now'),
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?
        )
    """, (
        client_ip,
        request.method,
        request.path,
        requests_per_sec,
        "NORMAL",
        "ALLOW",
        200
    ))

    conn.commit()
    conn.close()

    return None


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/")
@login_required
def dashboard():

    refresh_attack_status()

    return render_template(
        "dashboard.html"
    )


# ============================================================
# PROTECTED DEMO WEBSITE
# ============================================================

@app.route("/protected")
def protected():

    return """
    <!DOCTYPE html>

    <html>

    <head>

        <title>Protected Website</title>

        <style>

            body {
                margin: 0;
                background: #070b14;
                color: white;
                font-family: Arial;
                text-align: center;
            }

            .box {
                margin: 120px auto;
                max-width: 700px;
                padding: 50px;
                background: #101725;
                border: 1px solid #293951;
                border-radius: 20px;
            }

            h1 {
                color: #5cff91;
            }

            p {
                color: #9fb1cc;
                font-size: 18px;
            }

        </style>

    </head>

    <body>

        <div class="box">

            <h1>
                🛡️ Protected Website
            </h1>

            <p>
                This website is protected by CyberShield
                DDoS Protection System.
            </p>

            <p>
                Traffic is monitored and suspicious
                request bursts are automatically rate-limited.
            </p>

        </div>

    </body>

    </html>
    """


# ============================================================
# REAL STATISTICS API
# ============================================================

@app.route("/api/real-stats")
@login_required
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

    return jsonify({
        "total_requests": total,
        "normal_requests": normal,
        "suspicious_requests": suspicious,
        "rate_limited": rate_limited,
        "threshold": get_threshold()
    })


# ============================================================
# REAL TRAFFIC LOGS API
# ============================================================

@app.route("/api/real-logs")
@login_required
def real_logs():

    conn = get_db()

    rows = conn.execute("""
        SELECT
            id,
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

    return jsonify([
        dict(row)
        for row in rows
    ])


# ============================================================
# ALERTS API
# ============================================================

@app.route("/api/alerts")
@login_required
def alerts_api():

    conn = get_db()

    rows = conn.execute("""
        SELECT
            id,
            timestamp,
            client_ip,
            alert_type,
            severity,
            message,
            action

        FROM alerts

        ORDER BY id DESC

        LIMIT 100
    """).fetchall()

    conn.close()

    return jsonify([
        dict(row)
        for row in rows
    ])


# ============================================================
# ATTACK API
# ============================================================

@app.route("/api/attacks")
@login_required
def attacks_api():

    refresh_attack_status()

    conn = get_db()

    rows = conn.execute("""
        SELECT
            id,
            attack_type,
            source_ip,
            first_seen,
            last_seen,
            peak_rate,
            suspicious_requests,
            blocked_requests,
            severity,
            status

        FROM attack_events

        ORDER BY id DESC

        LIMIT 50
    """).fetchall()

    conn.close()

    return jsonify([
        dict(row)
        for row in rows
    ])


# ============================================================
# ATTACK SUMMARY
# ============================================================

@app.route("/api/attack-summary")
@login_required
def attack_summary():

    refresh_attack_status()

    conn = get_db()

    total = conn.execute("""
        SELECT COUNT(*) AS count
        FROM attack_events
    """).fetchone()["count"]

    active = conn.execute("""
        SELECT COUNT(*) AS count
        FROM attack_events
        WHERE status = 'ACTIVE'
    """).fetchone()["count"]

    mitigated = conn.execute("""
        SELECT COUNT(*) AS count
        FROM attack_events
        WHERE status = 'MITIGATED'
    """).fetchone()["count"]

    conn.close()

    return jsonify({
        "total": total,
        "active": active,
        "mitigated": mitigated
    })


# ============================================================
# SETTINGS API
# ============================================================

@app.route("/api/settings", methods=["GET"])
@login_required
def settings_get():

    return jsonify({
        "request_threshold": get_threshold(),
        "window_seconds": WINDOW_SECONDS,
        "attack_active_seconds": ATTACK_ACTIVE_SECONDS
    })


@app.route("/api/settings", methods=["POST"])
@login_required
def settings_update():

    data = request.get_json(silent=True) or {}

    try:

        threshold = int(
            data.get(
                "request_threshold",
                get_threshold()
            )
        )

    except (TypeError, ValueError):

        return jsonify({
            "success": False,
            "message": "Invalid threshold"
        }), 400

    if threshold < 1 or threshold > 10000:

        return jsonify({
            "success": False,
            "message": "Threshold must be between 1 and 10000"
        }), 400

    set_threshold(threshold)

    return jsonify({
        "success": True,
        "request_threshold": threshold
    })


# ============================================================
# OTHER PAGES
# ============================================================

@app.route("/traffic")
@login_required
def traffic():

    return render_template(
        "traffic.html"
    )


@app.route("/alerts")
@login_required
def alerts():

    return render_template(
        "alerts.html"
    )


@app.route("/logs")
@login_required
def logs():

    return render_template(
        "logs.html"
    )


@app.route("/settings")
@login_required
def settings():

    return render_template(
        "settings.html"
    )


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
