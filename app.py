from flask import (
    Flask,
    render_template,
    jsonify,
    request,
    redirect,
    url_for,
    session
)

import sqlite3
import time
from collections import defaultdict, deque
from functools import wraps


# ============================================================
# CYBERSHIELD APPLICATION
# ============================================================

app = Flask(__name__)

# Secret key used for login sessions
app.secret_key = "CyberShield-Secret-Key-2026-Change-Later"


# ============================================================
# CONFIGURATION
# ============================================================

DATABASE = "cybershield.db"

REQUEST_THRESHOLD = 20
WINDOW_SECONDS = 1


# Demo admin credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "CyberShield@2026"


# ============================================================
# REAL-TIME REQUEST TRACKER
# ============================================================

request_tracker = defaultdict(deque)


# ============================================================
# DATABASE
# ============================================================

def get_db_connection():

    conn = sqlite3.connect(DATABASE)

    conn.row_factory = sqlite3.Row

    return conn


def init_db():

    conn = get_db_connection()

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

    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            message TEXT NOT NULL,
            severity TEXT NOT NULL,
            requests_per_sec INTEGER NOT NULL,
            action TEXT NOT NULL
        )
    """)

    conn.commit()

    conn.close()


# ============================================================
# REAL CLIENT IP
# ============================================================

def get_client_ip():

    forwarded_for = request.headers.get(
        "X-Forwarded-For"
    )

    if forwarded_for:

        return forwarded_for.split(",")[0].strip()

    return request.remote_addr or "unknown"


# ============================================================
# REQUEST RATE CALCULATION
# ============================================================

def check_request_rate(client_ip):

    current_time = time.time()

    timestamps = request_tracker[client_ip]

    while (
        timestamps
        and timestamps[0]
        <= current_time - WINDOW_SECONDS
    ):

        timestamps.popleft()

    timestamps.append(current_time)

    return len(timestamps)


# ============================================================
# LOG REQUEST
# ============================================================

def log_real_request(
    client_ip,
    method,
    path,
    requests_per_sec,
    status,
    action,
    response_code
):

    conn = get_db_connection()

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
        method,
        path,
        requests_per_sec,
        status,
        action,
        response_code
    ))

    conn.commit()

    conn.close()


# ============================================================
# CREATE SECURITY ALERT
# ============================================================

def create_alert(
    message,
    severity,
    requests_per_sec,
    action
):

    conn = get_db_connection()

    conn.execute("""
        INSERT INTO alerts (
            timestamp,
            message,
            severity,
            requests_per_sec,
            action
        )

        VALUES (
            datetime('now'),
            ?,
            ?,
            ?,
            ?
        )
    """, (
        message,
        severity,
        requests_per_sec,
        action
    ))

    conn.commit()

    conn.close()


# ============================================================
# ADMIN LOGIN DECORATOR
# ============================================================

def login_required(function):

    @wraps(function)
    def decorated_function(*args, **kwargs):

        if not session.get("admin_logged_in"):

            return redirect(
                url_for("login")
            )

        return function(*args, **kwargs)

    return decorated_function


# ============================================================
# LOGIN PAGE
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    error = None

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        if (
            username == ADMIN_USERNAME
            and password == ADMIN_PASSWORD
        ):

            session["admin_logged_in"] = True

            return redirect(
                url_for("dashboard")
            )

        error = "Invalid username or password."

    return render_template(
        "login.html",
        error=error
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# ============================================================
# CYBERSHIELD REQUEST PROTECTION ENGINE
# ============================================================

@app.before_request
def cyber_shield_protection():

    # The protected customer website is public.
    # The CyberShield admin dashboard is protected separately.

    if not request.path.startswith(
        "/protected"
    ):

        return None

    if request.path.startswith(
        "/static/"
    ):

        return None

    client_ip = get_client_ip()

    current_rate = check_request_rate(
        client_ip
    )


    # --------------------------------------------------------
    # NORMAL REQUEST
    # --------------------------------------------------------

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


    # --------------------------------------------------------
    # SUSPICIOUS REQUEST
    # --------------------------------------------------------

    log_real_request(
        client_ip=client_ip,
        method=request.method,
        path=request.path,
        requests_per_sec=current_rate,
        status="SUSPICIOUS",
        action="RATE LIMIT",
        response_code=429
    )

    create_alert(
        message=(
            f"High request rate detected "
            f"from {client_ip}"
        ),
        severity="HIGH",
        requests_per_sec=current_rate,
        action="RATE LIMIT"
    )

    return jsonify({

        "error": "Too Many Requests",

        "message":
            "CyberShield rate limit exceeded.",

        "requests_per_second":
            current_rate,

        "threshold":
            REQUEST_THRESHOLD

    }), 429, {

        "Retry-After": "1"

    }


# ============================================================
# CYBERSHIELD DASHBOARD
# ============================================================

@app.route("/")
@login_required
def dashboard():

    return render_template(
        "dashboard.html"
    )


# ============================================================
# TRAFFIC PAGE
# ============================================================

@app.route("/traffic")
@login_required
def traffic():

    return render_template(
        "traffic.html"
    )


# ============================================================
# ALERTS PAGE
# ============================================================

@app.route("/alerts")
@login_required
def alerts():

    return render_template(
        "alerts.html"
    )


# ============================================================
# LOGS PAGE
# ============================================================

@app.route("/logs")
@login_required
def logs():

    return render_template(
        "logs.html"
    )


# ============================================================
# SETTINGS PAGE
# ============================================================

@app.route("/settings")
@login_required
def settings():

    return render_template(
        "settings.html"
    )


# ============================================================
# CUSTOMER / PROTECTED WEBSITE
# ============================================================

@app.route("/protected")
def protected():

    return """
    <!DOCTYPE html>

    <html lang="en">

    <head>

        <meta charset="UTF-8">

        <meta
            name="viewport"
            content="width=device-width, initial-scale=1.0"
        >

        <title>
            CyberShield Protected Website
        </title>

        <style>

            * {
                box-sizing: border-box;
            }

            body {

                margin: 0;

                min-height: 100vh;

                font-family:
                    Arial,
                    Helvetica,
                    sans-serif;

                background:
                    radial-gradient(
                        circle at top,
                        #102a43,
                        #050b14 60%
                    );

                color: white;

                display: flex;

                align-items: center;

                justify-content: center;
            }


            .container {

                width: 90%;

                max-width: 800px;

                padding: 45px;

                background:
                    rgba(
                        10,
                        20,
                        35,
                        0.85
                    );

                border:
                    1px solid
                    rgba(
                        0,
                        255,
                        200,
                        0.25
                    );

                border-radius: 20px;

                box-shadow:
                    0 0 40px
                    rgba(
                        0,
                        255,
                        200,
                        0.12
                    );

                text-align: center;
            }


            .shield {

                font-size: 70px;

                margin-bottom: 20px;
            }


            h1 {

                margin:
                    0 0 15px;

                color: #00ffc8;

                font-size: 38px;
            }


            .subtitle {

                color: #a9b7c6;

                font-size: 18px;

                margin-bottom: 35px;
            }


            .status {

                display: inline-block;

                padding:
                    12px 22px;

                border-radius: 30px;

                background:
                    rgba(
                        0,
                        255,
                        150,
                        0.12
                    );

                border:
                    1px solid
                    rgba(
                        0,
                        255,
                        150,
                        0.4
                    );

                color: #00ff9d;

                font-weight: bold;
            }


            .info {

                margin-top: 35px;

                padding: 20px;

                background:
                    rgba(
                        255,
                        255,
                        255,
                        0.04
                    );

                border-radius: 12px;

                color: #b9c5d0;

                line-height: 1.6;
            }

        </style>

    </head>


    <body>

        <div class="container">

            <div class="shield">
                🛡️
            </div>

            <h1>
                Protected Website
            </h1>

            <div class="subtitle">

                This website is protected
                by CyberShield.

            </div>


            <div class="status">

                ● CYBERSHIELD
                PROTECTION ACTIVE

            </div>


            <div class="info">

                Every request to this page
                is monitored by the
                CyberShield request
                protection engine.

                <br><br>

                Normal traffic is allowed.

                <br>

                Excessive request rates
                are automatically detected
                and rate-limited.

            </div>

        </div>

    </body>

    </html>
    """


# ============================================================
# REAL TRAFFIC LOG API
# ============================================================

@app.route("/api/real-logs")
@login_required
def real_logs():

    conn = get_db_connection()

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

    return jsonify([
        dict(row)
        for row in rows
    ])


# ============================================================
# REAL STATISTICS API
# ============================================================

@app.route("/api/real-stats")
@login_required
def real_stats():

    conn = get_db_connection()


    total_requests = conn.execute("""
        SELECT COUNT(*)
        FROM request_events
    """).fetchone()[0]


    normal_requests = conn.execute("""
        SELECT COUNT(*)
        FROM request_events
        WHERE status = 'NORMAL'
    """).fetchone()[0]


    suspicious_requests = conn.execute("""
        SELECT COUNT(*)
        FROM request_events
        WHERE status = 'SUSPICIOUS'
    """).fetchone()[0]


    rate_limited = conn.execute("""
        SELECT COUNT(*)
        FROM request_events
        WHERE action = 'RATE LIMIT'
    """).fetchone()[0]


    alerts = conn.execute("""
        SELECT COUNT(*)
        FROM alerts
    """).fetchone()[0]


    conn.close()


    return jsonify({

        "total_requests":
            total_requests,

        "normal_requests":
            normal_requests,

        "suspicious_requests":
            suspicious_requests,

        "rate_limited":
            rate_limited,

        "alerts":
            alerts,

        "threshold":
            REQUEST_THRESHOLD

    })


# ============================================================
# INITIALIZE DATABASE
# ============================================================

init_db()


# ============================================================
# LOCAL DEVELOPMENT
# ============================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
