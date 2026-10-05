"""
mock_target.py — Intentionally vulnerable demo target for ATLAS.

Purpose
-------
Stands up a small local HTTP service at http://127.0.0.1:5000 (plus a tiny
raw-socket "extra service" on 127.0.0.1:2121) with deliberately weak
endpoints so every ATLAS module — discovery, validation, exploitation,
risk scoring, and synthesis — has something real and non-empty to find.

Coverage map (module -> what it should trip here)
---------------------------------------------------
exploitation/
  probe_sqli_canary.py        -> /api/v2/auth/login (SQLi-marker bypass)
  probe_xss_canary.py         -> /support/ticket/<id>?title=... (reflected XSS)
  probe_rate_limiting.py      -> /api/v2/auth/reset (no throttling, ever)
  probe_unauth_route.py       -> /api/v2/admin/* (no auth check at all)
  probe_parameter_pollution.py-> /api/v2/search?role=...&role=... (HPP bypass)

validation/
  check_security_headers.py   -> global: no CSP/HSTS/X-Frame-Options/etc.
  check_cors_config.py        -> global: reflects Origin + allow-credentials
  check_service_banner.py     -> global: verbose Server header + banner port
  check_default_creds_banner.py -> banner port advertises default creds
  check_jwt_structure.py      -> weak HS256 secret + alg:none acceptance
  check_exposed_files.py      -> /.env, /.git/config, /backup.sql, etc.
  check_open_ports.py         -> extra listener on 127.0.0.1:2121
  check_tls_config.py         -> whole app is plain HTTP (absence = finding)
  check_exposed_files.py / check_default_creds_banner.py also see robots.txt

⚠️ SAFETY
---------
- Run this ONLY on localhost, on your own machine, for testing your own
  scanner. Never deploy it, expose it on a network, or point it at anyone
  else's infrastructure.
- Nothing here touches a real database or executes attacker-supplied code.
  Every "vulnerability" is simulated (pattern-matched, hardcoded, or simply
  absent hardening) so it's safely detectable without being genuinely
  exploitable beyond this toy app.

Setup
-----
    pip install flask pyjwt
    python mock_target.py
    # -> serving on http://127.0.0.1:5000
    # -> banner service on 127.0.0.1:2121

Then, in another terminal, run your existing pipeline against it, e.g.:
    python -c "from App.agent import AIOrchestratorAgent; \
               AIOrchestratorAgent().run_pipeline('http://127.0.0.1:5000')"
or start App/main.py and POST {"target": "http://127.0.0.1:5000"} to
/api/orchestration/scan from the frontend.
"""

from flask import Flask, request, jsonify, Response
import time
import base64
import hmac
import hashlib
import json
import socket
import threading

app = Flask(__name__)

# Intentionally hardcoded/weak — this is the "vulnerability" under test.
WEAK_JWT_SECRET = "supersecretkey123"

# In-memory "users" so /api/v2/users/{id} has something to leak (IDOR demo).
_FAKE_USERS = {
    i: {"id": i, "name": f"User {i}", "email": f"user{i}@acmecorp.io", "role": "user"}
    for i in range(1, 21)
}
_FAKE_USERS[1] = {"id": 1, "name": "Admin Account", "email": "admin@acmecorp.io", "role": "superadmin"}

# Track reset-endpoint hits to demonstrate the *absence* of rate limiting.
_reset_hits = 0

# Extra raw-socket "service" used to demo open-port + banner-grab findings.
BANNER_HOST = "127.0.0.1"
BANNER_PORT = 2121
BANNER_TEXT = (
    "220 AcmeFTP 1.2.0 (Unpatched) ready.\r\n"
    "220 Default account still active — login: admin / admin123\r\n"
)


def _sign_weak_jwt(payload: dict) -> str:
    """Builds a JWT signed with a hardcoded secret using HS256 — deliberately weak."""
    def b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = b64url(json.dumps(header).encode())
    payload_b64 = b64url(json.dumps(payload).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(WEAK_JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{b64url(signature)}"


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


# ---------------------------------------------------------------------------
# Global response hooks — CORS misconfig, verbose banner, missing headers.
# We deliberately do NOT add CSP/HSTS/X-Frame-Options/etc. anywhere, so
# check_security_headers.py should flag Missing Security Headers (CWE-693)
# on every route. check_cors_config.py should flag the reflected-origin +
# allow-credentials combo below. check_service_banner.py should flag the
# verbose, version-specific Server header.
# ---------------------------------------------------------------------------

@app.after_request
def _weaken_response(resp):
    origin = request.headers.get("Origin")
    resp.headers["Access-Control-Allow-Origin"] = origin if origin else "*"
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    resp.headers["Server"] = "Acme-API/1.0.0 (Werkzeug/2.0.1 Python/3.9.6)"
    return resp


# ---------------------------------------------------------------------------
# Root / health — used by port & service discovery.
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return jsonify({
        "service": "acme-demo-api",
        "version": "1.0.0",
        "status": "online",
    })


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/robots.txt")
def robots():
    # Deliberately points a crawler/scanner straight at the exposed files
    # and admin routes below — realistic "helpfully leaked" disclosure.
    body = (
        "User-agent: *\n"
        "Disallow: /.env\n"
        "Disallow: /.git/\n"
        "Disallow: /backup.sql\n"
        "Disallow: /config.php.bak\n"
        "Disallow: /api/v2/admin/\n"
    )
    return Response(body, mimetype="text/plain")


# ---------------------------------------------------------------------------
# Simulated SQL-Injection-style authentication bypass + default creds.
# No real database is involved — this just pattern-matches classic injection
# markers so a scanner's payloads reliably trigger a detectable "bypass".
# ---------------------------------------------------------------------------

SQLI_MARKERS = ["' or '1'='1", "' or 1=1", "\" or \"1\"=\"1", "union select"]
DEFAULT_CREDS = {("admin@acmecorp.io", "admin123"), ("admin", "admin"), ("admin", "admin123")}


@app.route("/api/v2/auth/login", methods=["POST"])
def login():
    body = request.get_json(silent=True) or {}
    email = str(body.get("email", "")).lower()
    password = str(body.get("password", ""))

    if any(marker in email for marker in SQLI_MARKERS):
        token = _sign_weak_jwt({"user": "admin", "role": "superadmin", "iat": int(time.time())})
        return jsonify({"token": token, "user": "admin", "role": "superadmin"}), 200

    if (email, password) in DEFAULT_CREDS:
        token = _sign_weak_jwt({"user": email, "role": "superadmin", "iat": int(time.time())})
        return jsonify({"token": token, "user": email, "role": "superadmin", "note": "default credentials"}), 200

    if email == "user@acmecorp.io" and password == "password123":
        token = _sign_weak_jwt({"user": email, "role": "user", "iat": int(time.time())})
        return jsonify({"token": token, "user": email, "role": "user"}), 200

    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/v2/auth/token", methods=["GET"])
def issue_token():
    """Issues a token signed with the hardcoded weak secret — simulates a
    frontend bundle leaking the signing key, letting any scanner that already
    knows/extracts WEAK_JWT_SECRET forge admin tokens."""
    token = _sign_weak_jwt({"user": "guest", "role": "user", "iat": int(time.time())})
    return jsonify({"token": token})


# ---------------------------------------------------------------------------
# Missing rate limiting on password reset — accepts unlimited requests.
# ---------------------------------------------------------------------------

@app.route("/api/v2/auth/reset", methods=["POST"])
def reset_password():
    global _reset_hits
    _reset_hits += 1
    # Always 200, regardless of how many times it's hit — no throttling,
    # no CAPTCHA, no lockout. That absence is the finding.
    return jsonify({"message": "If this email exists, a reset link was sent.", "attempt": _reset_hits})


# ---------------------------------------------------------------------------
# Reflected XSS — ticket title is echoed back unescaped in raw HTML.
# ---------------------------------------------------------------------------

@app.route("/support/ticket/<ticket_id>")
def support_ticket(ticket_id):
    title = request.args.get("title", "Untitled ticket")
    html = f"""<!doctype html>
<html><head><title>Ticket {ticket_id}</title></head>
<body><h1>Support Ticket #{ticket_id}</h1><p>Subject: {title}</p></body></html>"""
    return Response(html, mimetype="text/html")


# ---------------------------------------------------------------------------
# IDOR — no ownership/authorization check on user profile lookups.
# ---------------------------------------------------------------------------

@app.route("/api/v2/users/<int:user_id>")
def get_user(user_id):
    user = _FAKE_USERS.get(user_id)
    if not user:
        return jsonify({"error": "Not found"}), 404
    return jsonify(user)


# ---------------------------------------------------------------------------
# JWT structure weaknesses — hardcoded HS256 secret AND alg:none acceptance.
# check_jwt_structure.py should be able to flag both the guessable/known
# secret and the fact that this endpoint trusts an unsigned "none" token.
# ---------------------------------------------------------------------------

@app.route("/api/v2/account/profile")
def profile():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "Missing token"}), 401

    token = auth.split(" ", 1)[1]
    parts = token.split(".")
    if len(parts) != 3:
        return jsonify({"error": "Malformed token"}), 400

    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        return jsonify({"error": "Malformed token"}), 400

    # Deliberately vulnerable: accepts alg=none with no signature at all.
    if str(header.get("alg", "")).lower() == "none":
        return jsonify({"user": payload.get("user"), "role": payload.get("role"), "note": "alg=none accepted"})

    signing_input = f"{parts[0]}.{parts[1]}".encode()
    expected_sig = hmac.new(WEAK_JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
    expected_b64 = base64.urlsafe_b64encode(expected_sig).rstrip(b"=").decode()
    if not hmac.compare_digest(expected_b64, parts[2]):
        return jsonify({"error": "Invalid signature"}), 401

    return jsonify({"user": payload.get("user"), "role": payload.get("role")})


# ---------------------------------------------------------------------------
# Unauthenticated access to admin routes — probe_unauth_route.py target.
# These look protected by naming convention but perform no auth check.
# ---------------------------------------------------------------------------

@app.route("/api/v2/admin/dashboard")
def admin_dashboard():
    return jsonify({
        "total_users": len(_FAKE_USERS),
        "reset_attempts": _reset_hits,
        "internal_note": "no auth check on this route",
    })


@app.route("/api/v2/admin/users")
def admin_users():
    return jsonify({"users": list(_FAKE_USERS.values())})


# ---------------------------------------------------------------------------
# HTTP Parameter Pollution — probe_parameter_pollution.py target.
# The "role" check (what auth thinks is happening) reads the FIRST value;
# the actual filtering logic reads the LAST value. Supplying role twice
# lets a low-priv request smuggle an admin-only result set past the check.
# ---------------------------------------------------------------------------

@app.route("/api/v2/search")
def search():
    roles = request.args.getlist("role")
    queries = request.args.getlist("q")

    checked_role = roles[0] if roles else "guest"     # what the "auth" layer sees
    effective_role = roles[-1] if roles else "guest"  # what actually filters data
    query = queries[-1] if queries else ""

    if effective_role == "admin":
        results = list(_FAKE_USERS.values())
        bypass = checked_role != "admin"
    else:
        results = [u for u in _FAKE_USERS.values() if query.lower() in u["name"].lower()]
        bypass = False

    return jsonify({
        "checked_role": checked_role,
        "effective_role": effective_role,
        "parameter_pollution_bypass": bypass,
        "results": results,
    })


# ---------------------------------------------------------------------------
# Exposed sensitive files — check_exposed_files.py targets.
# ---------------------------------------------------------------------------

@app.route("/.env")
def exposed_env():
    body = (
        "APP_ENV=production\n"
        "DB_HOST=db.internal.acmecorp.io\n"
        "DB_USER=acme_admin\n"
        "DB_PASSWORD=Sup3rSecretProdPW!\n"
        "JWT_SECRET=supersecretkey123\n"
        "STRIPE_SECRET_KEY=sk_test_placeholder_key_for_testing_000\n"
    )
    return Response(body, mimetype="text/plain")


@app.route("/.git/config")
def exposed_git_config():
    body = (
        "[core]\n"
        "\trepositoryformatversion = 0\n"
        "\tfilemode = true\n"
        "[remote \"origin\"]\n"
        "\turl = https://ci-deploy:ghp_FAKEEXAMPLETOKEN0000000000@github.com/acmecorp/api.git\n"
    )
    return Response(body, mimetype="text/plain")


@app.route("/backup.sql")
def exposed_backup():
    body = (
        "-- acme-demo-api DB dump (fake, for scanner testing only)\n"
        "INSERT INTO users (email, password_hash, role) VALUES\n"
        "('admin@acmecorp.io', '$2y$10$FAKEHASHFAKEHASHFAKEHASH', 'superadmin');\n"
    )
    return Response(body, mimetype="application/sql")


@app.route("/config.php.bak")
def exposed_php_backup():
    body = (
        "<?php\n"
        "define('DB_HOST', 'db.internal.acmecorp.io');\n"
        "define('DB_USER', 'acme_admin');\n"
        "define('DB_PASS', 'Sup3rSecretProdPW!');\n"
        "?>\n"
    )
    return Response(body, mimetype="text/plain")


# ---------------------------------------------------------------------------
# Verbose error messages — malformed input trips an unhandled exception and
# (with debug=True) Flask serves a full stack trace.
# ---------------------------------------------------------------------------

@app.route("/api/v2/error-test")
def error_test():
    payload = request.args.get("value", "")
    # Deliberately unguarded int() conversion — non-numeric input raises.
    parsed = int(payload)
    return jsonify({"value": parsed})


# ---------------------------------------------------------------------------
# Extra "service" on a second port — check_open_ports.py /
# check_service_banner.py / check_default_creds_banner.py target.
# Plain socket, no Flask: just accepts a connection, sends a banner that
# both discloses version info and advertises unchanged default credentials,
# then closes. Never touches real FTP or any other real protocol/service.
# ---------------------------------------------------------------------------

def _run_banner_service():
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((BANNER_HOST, BANNER_PORT))
        srv.listen(5)
    except OSError as e:
        print(f"[banner-service] could not bind {BANNER_HOST}:{BANNER_PORT} ({e}); skipping.")
        return

    while True:
        try:
            conn, _addr = srv.accept()
            conn.sendall(BANNER_TEXT.encode())
            conn.close()
        except OSError:
            break


if __name__ == "__main__":
    print("=" * 60)
    print(" ATLAS Mock Target — intentionally vulnerable demo service")
    print(" LOCAL USE ONLY — do not expose this beyond 127.0.0.1")
    print("=" * 60)
    print("HTTP endpoints (port 5000):")
    print("  GET  /")
    print("  GET  /health")
    print("  GET  /robots.txt")
    print("  POST /api/v2/auth/login        (SQLi bypass + default creds demo)")
    print("  GET  /api/v2/auth/token        (weak JWT signing demo)")
    print("  POST /api/v2/auth/reset        (missing rate limiting demo)")
    print("  GET  /support/ticket/<id>?title=... (reflected XSS demo)")
    print("  GET  /api/v2/users/<id>        (IDOR demo)")
    print("  GET  /api/v2/account/profile   (JWT alg:none / weak-secret demo)")
    print("  GET  /api/v2/admin/dashboard   (unauthenticated admin route demo)")
    print("  GET  /api/v2/admin/users       (unauthenticated admin route demo)")
    print("  GET  /api/v2/search?role=&q=   (HTTP parameter pollution demo)")
    print("  GET  /.env, /.git/config, /backup.sql, /config.php.bak (exposed files demo)")
    print("  GET  /api/v2/error-test?value=... (verbose error demo)")
    print(f"Raw banner service: {BANNER_HOST}:{BANNER_PORT} (open port + default creds banner demo)")
    print("=" * 60)

    banner_thread = threading.Thread(target=_run_banner_service, daemon=True)
    banner_thread.start()

    # debug=True is intentional here so /api/v2/error-test demonstrates the
    # "verbose error / stack trace exposure" finding category.
    app.run(host="127.0.0.1", port=5000, debug=True, use_reloader=False)