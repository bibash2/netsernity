"""File-backed user store with PBKDF2-SHA256 password hashing."""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
from pathlib import Path
from typing import Optional

from .models import Role, User


class UserStore:

    def __init__(self, path: str = "data/users.json") -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
        self._users: dict[str, User] = {}
        self._load()

    @staticmethod
    def _hash_password(password: str, salt: str) -> str:
        return hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt.encode(), 100_000
        ).hex()

    def _load(self) -> None:
        if self._path.exists():
            with open(self._path) as f:
                data = json.load(f)
            for name, info in data.items():
                self._users[name] = User(
                    username=name,
                    password_hash=info["password_hash"],
                    salt=info["salt"],
                    role=Role(info["role"]),
                    full_name=info.get("full_name", ""),
                    active=info.get("active", True),
                )
        else:
            self._seed_defaults()

    def _seed_defaults(self) -> None:
        self.create_user("admin", "admin123", Role.ADMIN, "Administrator")
        self.create_user("viewer", "viewer123", Role.VIEWER, "Viewer")

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        data = {}
        for name, user in self._users.items():
            data[name] = {
                "password_hash": user.password_hash,
                "salt": user.salt,
                "role": user.role.value,
                "full_name": user.full_name,
                "active": user.active,
            }
        tmp = self._path.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        tmp.replace(self._path)

    def create_user(
        self, username: str, password: str, role: Role, full_name: str = ""
    ) -> User:
        with self._lock:
            if username in self._users:
                raise ValueError(f"User '{username}' already exists")
            salt = secrets.token_hex(16)
            user = User(
                username=username,
                password_hash=self._hash_password(password, salt),
                salt=salt,
                role=role,
                full_name=full_name,
            )
            self._users[username] = user
            self._save()
            return user

    def authenticate(self, username: str, password: str) -> Optional[User]:
        with self._lock:
            user = self._users.get(username)
            if not user or not user.active:
                return None
            if self._hash_password(password, user.salt) != user.password_hash:
                return None
            return user

    def get(self, username: str) -> Optional[User]:
        return self._users.get(username)

    def list_all(self) -> list[dict]:
        return [
            {
                "username": u.username,
                "role": u.role.value,
                "full_name": u.full_name,
                "active": u.active,
            }
            for u in self._users.values()
        ]

    def delete(self, username: str) -> bool:
        with self._lock:
            if username not in self._users:
                return False
            del self._users[username]
            self._save()
            return True

    def update_password(self, username: str, new_password: str) -> bool:
        with self._lock:
            user = self._users.get(username)
            if not user:
                return False
            user.salt = secrets.token_hex(16)
            user.password_hash = self._hash_password(new_password, user.salt)
            self._save()
            return True
