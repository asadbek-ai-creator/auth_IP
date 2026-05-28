import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

SALT_BYTES = 16
DB_FILE = Path(__file__).resolve().parent / "users_db.json"


@dataclass
class AuthResult:
    success: bool
    message: str
    steps: list[tuple[str, str]] = field(default_factory=list)


def _load_users() -> dict:
    if not DB_FILE.exists():
        return {}
    raw = DB_FILE.read_text(encoding="utf-8").strip()
    if not raw:
        return {}
    return json.loads(raw)


def _save_users(users: dict) -> None:
    DB_FILE.write_text(json.dumps(users, indent=2), encoding="utf-8")


def _hash_password(password: str, salt: bytes) -> str:
    return hashlib.sha256(salt + password.encode("utf-8")).hexdigest()


def register_user(username: str, password: str) -> AuthResult:
    username = username.strip()
    steps: list[tuple[str, str]] = []
    steps.append(("SYSTEM", f"Registration initiated for user '{username or '<empty>'}'."))

    if not username:
        steps.append(("ERROR", "Username cannot be empty."))
        return AuthResult(False, "Username cannot be empty.", steps)
    if not password:
        steps.append(("ERROR", "Password cannot be empty."))
        return AuthResult(False, "Password cannot be empty.", steps)

    steps.append(("STEP", "Loading existing user database (users_db.json)..."))
    users = _load_users()

    if username in users:
        steps.append(("ERROR", f"User '{username}' already exists in database."))
        return AuthResult(False, "Username already exists.", steps)

    steps.append(("STEP", f"Generating {SALT_BYTES}-byte random salt via os.urandom..."))
    salt = os.urandom(SALT_BYTES)
    salt_hex = salt.hex()
    steps.append(("SALT", salt_hex))

    pw_bytes = len(password.encode("utf-8"))
    steps.append((
        "STEP",
        f"Concatenating salt ({SALT_BYTES} bytes) + password ({pw_bytes} bytes, utf-8 encoded)...",
    ))
    steps.append(("STEP", "Applying SHA-256 cryptographic hash function..."))
    pw_hash = _hash_password(password, salt)
    steps.append(("RESULT", pw_hash))

    steps.append(("STEP", "Persisting record {salt, hash} to users_db.json..."))
    users[username] = {"salt": salt_hex, "hash": pw_hash}
    _save_users(users)

    steps.append(("SUCCESS", f"User '{username}' securely stored."))
    return AuthResult(True, f"User '{username}' registered successfully.", steps)


def login_user(username: str, password: str) -> AuthResult:
    username = username.strip()
    steps: list[tuple[str, str]] = []
    steps.append(("SYSTEM", f"Login attempt for user '{username or '<empty>'}'."))

    if not username:
        steps.append(("ERROR", "Username cannot be empty."))
        return AuthResult(False, "Username cannot be empty.", steps)
    if not password:
        steps.append(("ERROR", "Password cannot be empty."))
        return AuthResult(False, "Password cannot be empty.", steps)

    steps.append(("STEP", "Loading user record from users_db.json..."))
    users = _load_users()
    record = users.get(username)
    if record is None:
        steps.append(("ERROR", f"User '{username}' not found in database."))
        return AuthResult(False, "User not found.", steps)

    stored_salt_hex = record["salt"]
    stored_hash = record["hash"]
    steps.append(("SALT", f"Retrieved stored salt: {stored_salt_hex}"))
    steps.append(("HASH", f"Retrieved stored hash: {stored_hash}"))

    pw_bytes = len(password.encode("utf-8"))
    steps.append((
        "STEP",
        f"Re-hashing input password ({pw_bytes} bytes) with the retrieved salt (SHA-256)...",
    ))
    salt = bytes.fromhex(stored_salt_hex)
    computed = _hash_password(password, salt)
    steps.append(("RESULT", f"Computed hash: {computed}"))

    steps.append(("STEP", "Comparing stored vs. computed hash using hmac.compare_digest (constant-time)..."))
    if hmac.compare_digest(stored_hash, computed):
        steps.append(("MATCH", "Hashes match."))
        steps.append(("SUCCESS", f"Authentication successful. Welcome back, {username}!"))
        return AuthResult(True, f"Welcome back, {username}!", steps)

    steps.append(("MISMATCH", "Hashes do not match."))
    steps.append(("ERROR", "Hash mismatch — incorrect password."))
    return AuthResult(False, "Incorrect password.", steps)
