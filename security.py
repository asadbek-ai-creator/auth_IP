"""Cryptographic primitives + step-by-step educational trace.

Pure functions — no I/O, no database. The Flask layer composes these
with `database.py` to build a complete AuthResult.
"""

import hashlib
import hmac
import os
from dataclasses import dataclass, field

SALT_BYTES = 16
HASH_ALGO = "SHA-256"


@dataclass
class CryptoTrace:
    """Result of a crypto operation plus the educational steps it produced."""
    success: bool
    message: str
    steps: list[tuple[str, str]] = field(default_factory=list)
    salt_hex: str = ""
    hash_hex: str = ""


def _sha256_hex(salt: bytes, password: str) -> str:
    return hashlib.sha256(salt + password.encode("utf-8")).hexdigest()


def hash_new_password(password: str) -> CryptoTrace:
    """Generate a fresh salt and hash a new password. Used on registration."""
    steps: list[tuple[str, str]] = []
    steps.append(("STEP", f"Generating {SALT_BYTES}-byte cryptographic salt via os.urandom..."))

    salt = os.urandom(SALT_BYTES)
    salt_hex = salt.hex()
    steps.append(("SALT", salt_hex))

    pw_bytes = len(password.encode("utf-8"))
    steps.append((
        "STEP",
        f"Concatenating salt ({SALT_BYTES} bytes) + password ({pw_bytes} bytes, utf-8)...",
    ))
    steps.append(("STEP", f"Applying {HASH_ALGO} cryptographic hash function..."))

    pw_hash = _sha256_hex(salt, password)
    steps.append(("RESULT", pw_hash))

    return CryptoTrace(
        success=True,
        message="Password hashed successfully.",
        steps=steps,
        salt_hex=salt_hex,
        hash_hex=pw_hash,
    )


def verify_password(password: str, stored_salt_hex: str, stored_hash: str) -> CryptoTrace:
    """Re-hash an input password with a stored salt and compare in constant time."""
    steps: list[tuple[str, str]] = []
    steps.append(("SALT", f"Retrieved stored salt: {stored_salt_hex}"))
    steps.append(("HASH", f"Retrieved stored hash: {stored_hash}"))

    pw_bytes = len(password.encode("utf-8"))
    steps.append((
        "STEP",
        f"Re-hashing input password ({pw_bytes} bytes) with the retrieved salt ({HASH_ALGO})...",
    ))

    salt = bytes.fromhex(stored_salt_hex)
    computed = _sha256_hex(salt, password)
    steps.append(("RESULT", f"Computed hash: {computed}"))

    steps.append(("STEP", "Comparing stored vs. computed hash using hmac.compare_digest (constant-time)..."))
    matched = hmac.compare_digest(stored_hash, computed)
    if matched:
        steps.append(("MATCH", "Hashes match — credentials valid."))
        return CryptoTrace(True, "Authentication successful.", steps, stored_salt_hex, computed)

    steps.append(("MISMATCH", "Hashes do not match — incorrect password."))
    return CryptoTrace(False, "Incorrect password.", steps, stored_salt_hex, computed)
