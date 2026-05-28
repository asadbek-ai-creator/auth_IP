"""Flask entrypoint — wires security.py + database.py together and renders
the single-page educational UI."""

import os
from datetime import datetime

from flask import Flask, render_template, request

import database
import security

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32)


@app.before_request
def _ensure_schema() -> None:
    database.init_db()


def _build_trace(action: str, steps: list[tuple[str, str]]) -> dict:
    return {
        "action": action,
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "steps": steps,
    }


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", trace=None, status=None, username="")


@app.route("/register", methods=["POST"])
def register():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    steps: list[tuple[str, str]] = []
    steps.append(("SYSTEM", f"Registration initiated for user '{username or '<empty>'}'."))

    if not username:
        steps.append(("ERROR", "Username cannot be empty."))
        return _render(steps, "REGISTER", success=False, message="Username cannot be empty.", username=username)
    if not password:
        steps.append(("ERROR", "Password cannot be empty."))
        return _render(steps, "REGISTER", success=False, message="Password cannot be empty.", username=username)

    steps.append(("STEP", "Checking SQLite for existing username..."))
    if database.get_user(username) is not None:
        steps.append(("ERROR", f"User '{username}' already exists in database."))
        return _render(steps, "REGISTER", success=False, message="Username already exists.", username=username)

    trace = security.hash_new_password(password)
    steps.extend(trace.steps)

    steps.append(("STEP", "Persisting record into SQLite (users table)..."))
    created = database.create_user(username, trace.salt_hex, trace.hash_hex)
    if not created:
        steps.append(("ERROR", "Insert failed due to a race on the unique constraint."))
        return _render(steps, "REGISTER", success=False, message="Username already exists.", username=username)

    steps.append(("SUCCESS", f"User '{username}' securely stored."))
    return _render(steps, "REGISTER", success=True, message=f"User '{username}' registered.", username=username)


@app.route("/login", methods=["POST"])
def login():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    steps: list[tuple[str, str]] = []
    steps.append(("SYSTEM", f"Login attempt for user '{username or '<empty>'}'."))

    if not username:
        steps.append(("ERROR", "Username cannot be empty."))
        return _render(steps, "LOGIN", success=False, message="Username cannot be empty.", username=username)
    if not password:
        steps.append(("ERROR", "Password cannot be empty."))
        return _render(steps, "LOGIN", success=False, message="Password cannot be empty.", username=username)

    steps.append(("STEP", "Loading user record from SQLite..."))
    record = database.get_user(username)
    if record is None:
        steps.append(("ERROR", f"User '{username}' not found in database."))
        return _render(steps, "LOGIN", success=False, message="User not found.", username=username)

    trace = security.verify_password(password, record["salt"], record["hash"])
    steps.extend(trace.steps)

    if trace.success:
        steps.append(("SUCCESS", f"Authentication successful. Welcome back, {username}!"))
        return _render(steps, "LOGIN", success=True, message=f"Welcome back, {username}!", username=username)

    steps.append(("ERROR", "Hash mismatch — incorrect password."))
    return _render(steps, "LOGIN", success=False, message="Incorrect password.", username=username)


def _render(steps, action, *, success, message, username):
    return render_template(
        "index.html",
        trace=_build_trace(action, steps),
        status={"success": success, "message": message},
        username=username,
    )


if __name__ == "__main__":
    database.init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
