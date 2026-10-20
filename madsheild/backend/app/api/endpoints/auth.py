"""Authentication endpoints: register, login, me, logout."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

from ...services import auth as auth_service

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class RegisterRequest(BaseModel):
    identifier: Optional[str] = Field(default=None, min_length=1, max_length=320)
    email: Optional[str] = Field(default=None, min_length=1, max_length=320)
    password: str = Field(min_length=6, max_length=256)

    def resolved_identifier(self) -> str:
        value = (self.identifier or self.email or "").strip()
        if not value:
            raise ValueError("ID is required.")
        return value


class LoginRequest(BaseModel):
    identifier: Optional[str] = Field(default=None, min_length=1, max_length=320)
    email: Optional[str] = Field(default=None, min_length=1, max_length=320)
    password: str = Field(min_length=1, max_length=256)

    def resolved_identifier(self) -> str:
        value = (self.identifier or self.email or "").strip()
        if not value:
            raise ValueError("ID is required.")
        return value


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict[str, Any]


@router.post("/register", response_model=TokenResponse)
def register(payload: RegisterRequest) -> TokenResponse:
    try:
        identifier = payload.resolved_identifier()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    try:
        user = auth_service.register_user(identifier, payload.password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    token = auth_service.create_access_token(str(user["id"]), str(user["identifier"]))
    return TokenResponse(
        access_token=token,
        user=auth_service.user_without_hash(user),
    )


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest) -> TokenResponse:
    try:
        identifier = payload.resolved_identifier()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    user = auth_service.authenticate_user(identifier, payload.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid ID or password.")
    token = auth_service.create_access_token(str(user["id"]), str(user["identifier"]))
    return TokenResponse(
        access_token=token,
        user=auth_service.user_without_hash(user),
    )


@router.get("/me")
def me(
    authorization: Optional[str] = Header(default=None, alias="authorization"),
) -> dict[str, Any]:
    token: Optional[str] = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization[len("Bearer "):]
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    data = auth_service.decode_token(token)
    if not data:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")
    subject = data.get("sub")
    if not isinstance(subject, str) or not subject:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")
    user = auth_service.get_user_by_id(auth_service.load_users(), subject)
    if not user or not user.get("is_active"):
        raise HTTPException(status_code=401, detail="User not found or inactive.")
    return auth_service.user_without_hash(user)


@router.post("/logout")
def logout() -> dict[str, str]:
    return {"detail": "Logged out."}
