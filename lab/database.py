"""SQLite setup with synthetic data and salted password hashes."""

import hashlib
import hmac
import secrets
import sqlite3
from contextlib import contextmanager
from pathlib import Path


def hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(salt), 600_000
    ).hex()


def password_matches(password: str, user: sqlite3.Row) -> bool:
    return hmac.compare_digest(hash_password(password, user["salt"]), user["password_hash"])


@contextmanager
def connect(path: Path):
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    try:
        yield db
    finally:
        db.close()


def initialize(path: Path) -> None:
    with connect(path) as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY,
                owner_id INTEGER NOT NULL REFERENCES users(id),
                title TEXT NOT NULL,
                body TEXT NOT NULL
            );
        """)
        # Public demo credentials, never real accounts.
        for user_id, username, password, is_admin in [
            (1, "alice", "alice-demo-password", 0),
            (2, "bob", "bob-demo-password", 0),
            (3, "admin", "admin-demo-password", 1),
        ]:
            if db.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone():
                continue
            salt = secrets.token_hex(16)
            db.execute(
                "INSERT INTO users VALUES (?, ?, ?, ?, ?)",
                (user_id, username, hash_password(password, salt), salt, is_admin),
            )
        db.executemany(
            "INSERT OR IGNORE INTO notes VALUES (?, ?, ?, ?)",
            [
                (1, 1, "Alice shopping", "Synthetic note: buy apples."),
                (2, 2, "Bob private plan", "Synthetic note: Bob's interview is Friday."),
                (3, 3, "Admin checklist", "Synthetic note: review demo accounts."),
            ],
        )
        db.commit()
