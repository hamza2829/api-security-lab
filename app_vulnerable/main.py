"""Four deliberate bugs, kept separate from the secure baseline code."""

import os
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from lab.database import connect, initialize, password_matches


class Login(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=200)


def create_app(database_path: Path | None = None) -> FastAPI:
    path = database_path or Path(os.environ.get("LAB_DB_PATH", "vulnerable.db"))

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        initialize(path)
        yield

    app = FastAPI(title="API Security Lab: vulnerable", lifespan=lifespan)
    bearer = HTTPBearer(auto_error=False)

    # VULN-3: A known signing key allows forgery; expiry verification is disabled.
    jwt_secret = "secret123"

    def current_user(
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    ):
        if credentials is None:
            raise HTTPException(401, "Bearer token required")
        try:
            claims = jwt.decode(
                credentials.credentials,
                jwt_secret,
                algorithms=["HS256"],
                options={"verify_exp": False, "require": ["sub"]},
            )
            with connect(path) as db:
                user = db.execute(
                    "SELECT id, username, is_admin FROM users WHERE id = ?",
                    (claims["sub"],),
                ).fetchone()
        except (jwt.InvalidTokenError, sqlite3.Error):
            raise HTTPException(401, "Invalid token") from None
        if user is None:
            raise HTTPException(401, "Unknown user")
        return user

    @app.post("/login")
    def login(data: Login):
        with connect(path) as db:
            user = db.execute(
                "SELECT * FROM users WHERE username = ?", (data.username,)
            ).fetchone()
        if user is None or not password_matches(data.password, user):
            raise HTTPException(401, "Invalid credentials")
        token = jwt.encode(
            {"sub": str(user["id"]), "exp": datetime.now(timezone.utc) + timedelta(minutes=15)},
            jwt_secret,
            algorithm="HS256",
        )
        return {"access_token": token, "token_type": "bearer"}

    @app.get("/notes/{note_id}")
    def get_note(note_id: int, user=Depends(current_user)):
        with connect(path) as db:
            note = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
        if note is None:
            raise HTTPException(404, "Note not found")
        # VULN-1: The note is returned without checking note.owner_id against user.id.
        return dict(note)

    @app.get("/search")
    def search(q: str = "", user=Depends(current_user)):
        # VULN-2: Attacker input becomes SQL syntax instead of a bound value.
        query = (
            "SELECT id, title, body FROM notes "
            f"WHERE owner_id = {user['id']} AND title LIKE '%{q}%'"
        )
        with connect(path) as db:
            try:
                rows = db.execute(query).fetchall()
            except sqlite3.Error:
                raise HTTPException(400, "Invalid search") from None
        return [dict(row) for row in rows]

    @app.get("/admin/users")
    def list_users(user=Depends(current_user)):
        if not user["is_admin"]:
            raise HTTPException(403, "Admin required")
        with connect(path) as db:
            rows = db.execute("SELECT id, username, is_admin FROM users").fetchall()
        return [dict(row) for row in rows]

    return app


app = create_app()
