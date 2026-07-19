"""Auth API routes — login, user profile, user management."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from .models import Role
from .store import UserStore
from .jwt_handler import JWTHandler


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    token: str
    username: str
    role: str
    full_name: str
    expires_in: int


class CreateUserRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=32, pattern=r"^[a-zA-Z0-9_]+$")
    password: str = Field(..., min_length=6)
    role: str = Field(..., pattern=r"^(admin|operator|viewer)$")
    full_name: str = ""


class UserResponse(BaseModel):
    username: str
    role: str
    full_name: str
    active: bool


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=6)


def build_auth_router(
    store: UserStore, jwt: JWTHandler, expiry_seconds: int
) -> APIRouter:
    from ..api.dependencies import get_current_user, require_role

    router = APIRouter(tags=["Auth"])

    @router.post("/auth/login", response_model=LoginResponse)
    def login(req: LoginRequest):
        user = store.authenticate(req.username, req.password)
        if user is None:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "Invalid username or password"
            )
        token = jwt.create_token(user.username, user.role.value, user.full_name)
        return LoginResponse(
            token=token,
            username=user.username,
            role=user.role.value,
            full_name=user.full_name,
            expires_in=expiry_seconds,
        )

    @router.get("/auth/me", response_model=UserResponse)
    def me(user: dict = Depends(get_current_user)):
        stored = store.get(user["sub"])
        if not stored:
            raise HTTPException(404, "User not found")
        return UserResponse(
            username=stored.username,
            role=stored.role.value,
            full_name=stored.full_name,
            active=stored.active,
        )

    @router.put("/auth/me/password")
    def change_own_password(
        req: ChangePasswordRequest, user: dict = Depends(get_current_user)
    ):
        if not store.authenticate(user["sub"], req.current_password):
            raise HTTPException(400, "Current password is incorrect")
        store.update_password(user["sub"], req.new_password)
        return {"updated": True}

    @router.get(
        "/auth/users",
        response_model=list[UserResponse],
        dependencies=[Depends(require_role("admin"))],
    )
    def list_users():
        return [UserResponse(**u) for u in store.list_all()]

    @router.post(
        "/auth/users",
        response_model=UserResponse,
        status_code=201,
        dependencies=[Depends(require_role("admin"))],
    )
    def create_user(req: CreateUserRequest):
        try:
            user = store.create_user(
                req.username, req.password, Role(req.role), req.full_name
            )
        except ValueError as e:
            raise HTTPException(409, str(e))
        return UserResponse(
            username=user.username,
            role=user.role.value,
            full_name=user.full_name,
            active=user.active,
        )

    @router.delete(
        "/auth/users/{username}",
        dependencies=[Depends(require_role("admin"))],
    )
    def delete_user(username: str, user: dict = Depends(get_current_user)):
        if username == user["sub"]:
            raise HTTPException(400, "Cannot delete your own account")
        if not store.delete(username):
            raise HTTPException(404, f"User '{username}' not found")
        return {"deleted": True, "username": username}

    return router
