"""Authentication: user store, password hashing, JWT tokens."""

from __future__ import annotations

import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from jose import JWTError, jwt
from passlib.context import CryptContext

from ..config import STORAGE_DIR


SECRET_KEY = os.getenv("AUTH_SECRET_KEY", secrets.token_hex(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(
    os.getenv("AUTH_ACCESS_TOKEN_EXPIRE_MINUTES", "1440")
)  # 24 hours

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

USERS_FILE = STORAGE_DIR / "users.json"


def _load_users() -> dict[str, dict[str, Any]]:
    if not USERS_FILE.exists():
        return {}
    try:
        with open(USERS_FILE) as f:
            data: dict[str, dict[str, Any]] = json.load(f)
            return data
    except (json.JSONDecodeError, OSError):
        return {}


def _save_users(users: dict[str, dict[str, Any]]) -> None:
    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(user_id: str, identifier: str) -> str:
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": user_id,
        "identifier": identifier,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict[str, Any] | None:
    try:
        payload: dict[str, Any] = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


def get_user_by_identifier(
    users: dict[str, dict[str, Any]], identifier: str
) -> dict[str, Any] | None:
    wanted = identifier.strip().lower()
    for user in users.values():
        stored = str(user.get("identifier", user.get("email", ""))).strip().lower()
        if stored and stored == wanted:
            return user
    return None


def get_user_by_email(
    users: dict[str, dict[str, Any]], email: str
) -> dict[str, Any] | None:
    """Backwards-compatible alias (old user records used ``email``)."""
    return get_user_by_identifier(users, email)


def get_user_by_id(
    users: dict[str, dict[str, Any]], user_id: str
) -> dict[str, Any] | None:
    return users.get(user_id)


def user_without_hash(user: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in user.items() if k != "password_hash"}


def load_users() -> dict[str, dict[str, Any]]:
    """Public accessor for the user store (used by API layer)."""
    return _load_users()


def register_user(identifier: str, password: str) -> dict[str, Any]:
    identifier = identifier.strip()
    if not identifier:
        raise ValueError("ID is required.")
    if len(password) < 6:
        raise ValueError("Password must be at least 6 characters.")
    users = _load_users()
    if get_user_by_identifier(users, identifier):
        raise ValueError("ID already registered.")
    user_id = str(uuid4())
    users[user_id] = {
        "id": user_id,
        "identifier": identifier,
        "email": identifier,
        "password_hash": hash_password(password),
        "provider": "local",
        "provider_id": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "is_active": True,
    }
    _save_users(users)
    return users[user_id]


def authenticate_user(identifier: str, password: str) -> dict[str, Any] | None:
    users = _load_users()
    user = get_user_by_identifier(users, identifier)
    if not user or not user.get("password_hash"):
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    return user
