"""The same small API with ownership, SQL, and JWT checks repaired."""

import os
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from app_fixed.config import load_jwt_secret
from lab.database import connect, initialize, password_matches


class Login(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=200)


def create_app(database_path: Path | None = None) -> FastAPI:
    path = database_path or Path(os.environ.get("LAB_DB_PATH", "fixed.db"))

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.jwt_secret = load_jwt_secret()
        initialize(path)
        yield

    app = FastAPI(title="API Security Lab: fixed", lifespan=lifespan)
    bearer = HTTPBearer(auto_error=False)

    def current_user(
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    ):
        if credentials is None:
            raise HTTPException(401, "Bearer token required")
        try:
            claims = jwt.decode(
                credentials.credentials,
                app.state.jwt_secret,
                algorithms=["HS256"],
                options={"require": ["sub", "exp"]},
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
            app.state.jwt_secret,
            algorithm="HS256",
        )
        return {"access_token": token, "token_type": "bearer"}

    @app.get("/notes/{note_id}")
    def get_note(note_id: int, user=Depends(current_user)):
        with connect(path) as db:
            note = db.execute(
                "SELECT * FROM notes WHERE id = ? AND owner_id = ?",
                (note_id, user["id"]),
            ).fetchone()
        if note is None:
            raise HTTPException(404, "Note not found")
        return dict(note)

    @app.get("/search")
    def search(q: str = "", user=Depends(current_user)):
        query = (
            "SELECT id, title, body FROM notes "
            "WHERE owner_id = ? AND title LIKE ?"
        )
        with connect(path) as db:
            try:
                rows = db.execute(query, (user["id"], f"%{q}%")).fetchall()
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
