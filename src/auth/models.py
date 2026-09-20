"""User and role models for NetSentry access control."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Role(str, Enum):
    ADMIN = "admin"
    VIEWER = "viewer"


@dataclass
class User:
    username: str
    password_hash: str
    salt: str
    role: Role
    full_name: str = ""
    active: bool = True
