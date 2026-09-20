"""Tests for authentication, JWT, user store, and role-based access control."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.auth.jwt_handler import JWTHandler
from src.auth.models import Role
from src.auth.store import UserStore


# ── JWT Handler ──────────────────────────────────────────────────────────


class TestJWTHandler:
    def test_create_and_verify(self):
        jwt = JWTHandler("test-secret", expiry_seconds=3600)
        token = jwt.create_token("alice", "admin", "Alice Admin")
        payload = jwt.verify_token(token)
        assert payload is not None
        assert payload["sub"] == "alice"
        assert payload["role"] == "admin"
        assert payload["name"] == "Alice Admin"
        assert payload["exp"] > time.time()

    def test_expired_token_rejected(self):
        jwt = JWTHandler("test-secret", expiry_seconds=0)
        token = jwt.create_token("bob", "viewer")
        time.sleep(1)
        assert jwt.verify_token(token) is None

    def test_tampered_token_rejected(self):
        jwt = JWTHandler("test-secret", expiry_seconds=3600)
        token = jwt.create_token("alice", "admin")
        parts = token.split(".")
        parts[1] = parts[1][::-1]
        tampered = ".".join(parts)
        assert jwt.verify_token(tampered) is None

    def test_wrong_secret_rejected(self):
        jwt1 = JWTHandler("secret-1", expiry_seconds=3600)
        jwt2 = JWTHandler("secret-2", expiry_seconds=3600)
        token = jwt1.create_token("alice", "admin")
        assert jwt2.verify_token(token) is None

    def test_malformed_token_rejected(self):
        jwt = JWTHandler("test-secret")
        assert jwt.verify_token("not.a.valid.jwt.token") is None
        assert jwt.verify_token("garbage") is None
        assert jwt.verify_token("") is None


# ── User Store ───────────────────────────────────────────────────────────


class TestUserStore:
    @pytest.fixture()
    def store(self, tmp_path):
        return UserStore(path=str(tmp_path / "users.json"))

    def test_seeds_default_users(self, store):
        users = store.list_all()
        usernames = {u["username"] for u in users}
        assert {"admin", "viewer"} == usernames

    def test_authenticate_default_admin(self, store):
        user = store.authenticate("admin", "admin123")
        assert user is not None
        assert user.role == Role.ADMIN

    def test_wrong_password_rejected(self, store):
        assert store.authenticate("admin", "wrong") is None

    def test_nonexistent_user_rejected(self, store):
        assert store.authenticate("nobody", "pass") is None

    def test_create_and_authenticate(self, store):
        store.create_user("alice", "alice_pass", Role.ADMIN, "Alice Admin")
        user = store.authenticate("alice", "alice_pass")
        assert user is not None
        assert user.role == Role.ADMIN
        assert user.full_name == "Alice Admin"

    def test_duplicate_user_raises(self, store):
        with pytest.raises(ValueError, match="already exists"):
            store.create_user("admin", "pass", Role.VIEWER)

    def test_delete_user(self, store):
        assert store.delete("viewer") is True
        assert store.authenticate("viewer", "viewer123") is None
        assert store.delete("viewer") is False

    def test_update_password(self, store):
        assert store.update_password("viewer", "new_pass") is True
        assert store.authenticate("viewer", "viewer123") is None
        assert store.authenticate("viewer", "new_pass") is not None

    def test_persistence(self, tmp_path):
        path = str(tmp_path / "users.json")
        store1 = UserStore(path=path)
        store1.create_user("persist_user", "pass123", Role.VIEWER)

        store2 = UserStore(path=path)
        assert store2.authenticate("persist_user", "pass123") is not None


# ── API Auth Endpoints ───────────────────────────────────────────────────

MODELS_DIR = ROOT / "models_artifacts"
REQUIRED = ["preprocessor.pkl", "ensemble.pkl"]

pytestmark_models = pytest.mark.skipif(
    not all((MODELS_DIR / f).exists() for f in REQUIRED),
    reason="Model artifacts missing.",
)


@pytest.fixture(scope="module")
def auth_app(tmp_path_factory):
    """Create a test app with auth ENABLED."""
    from src.api.app import create_app
    from src.utils.config import load_config

    cfg = load_config("config/config.yaml")
    cfg.api.api_key = ""
    cfg.auth.enabled = True
    cfg.auth.jwt_secret = "test-secret-key"
    cfg.auth.token_expiry_hours = 1
    cfg.auth.users_file = str(tmp_path_factory.mktemp("auth") / "users.json")
    return create_app(cfg)


@pytest.fixture(scope="module")
def auth_client(auth_app) -> TestClient:
    return TestClient(auth_app)


def _login(client, username="admin", password="admin123") -> str:
    r = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200
    return r.json()["token"]


class TestAuthAPI:
    def test_login_success(self, auth_client):
        r = auth_client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "admin123"},
        )
        assert r.status_code == 200
        body = r.json()
        assert "token" in body
        assert body["username"] == "admin"
        assert body["role"] == "admin"

    def test_login_wrong_password(self, auth_client):
        r = auth_client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "wrong"},
        )
        assert r.status_code == 401

    def test_login_nonexistent_user(self, auth_client):
        r = auth_client.post(
            "/api/v1/auth/login",
            json={"username": "nobody", "password": "pass"},
        )
        assert r.status_code == 401

    def test_me_with_token(self, auth_client):
        token = _login(auth_client)
        r = auth_client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}
        )
        assert r.status_code == 200
        assert r.json()["username"] == "admin"
        assert r.json()["role"] == "admin"

    def test_me_without_token(self, auth_client):
        r = auth_client.get("/api/v1/auth/me")
        assert r.status_code == 401

    def test_me_with_invalid_token(self, auth_client):
        r = auth_client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer invalid.token.here"},
        )
        assert r.status_code == 401


class TestRBAC:
    def test_protected_endpoint_no_auth(self, auth_client):
        r = auth_client.get("/api/v1/stats")
        assert r.status_code == 401

    def test_protected_endpoint_with_viewer(self, auth_client):
        token = _login(auth_client, "viewer", "viewer123")
        r = auth_client.get(
            "/api/v1/stats", headers={"Authorization": f"Bearer {token}"}
        )
        assert r.status_code == 200

    @pytestmark_models
    def test_predict_requires_admin(self, auth_client):
        viewer_token = _login(auth_client, "viewer", "viewer123")
        r = auth_client.post(
            "/api/v1/predict",
            json={"flow": {"flow_duration": 1000}, "source_ip": "1.2.3.4"},
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert r.status_code == 403

    @pytestmark_models
    def test_predict_allowed_for_admin(self, auth_client):
        admin_token = _login(auth_client)
        r = auth_client.post(
            "/api/v1/predict",
            json={"flow": {"flow_duration": 1000}, "source_ip": "1.2.3.4"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200

    def test_admin_user_management(self, auth_client):
        admin_token = _login(auth_client)

        r = auth_client.get(
            "/api/v1/auth/users",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
        assert len(r.json()) >= 2

    def test_viewer_cannot_manage_users(self, auth_client):
        viewer_token = _login(auth_client, "viewer", "viewer123")

        r = auth_client.get(
            "/api/v1/auth/users",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert r.status_code == 403


class TestUserManagement:
    def test_create_user(self, auth_client):
        admin_token = _login(auth_client)

        r = auth_client.post(
            "/api/v1/auth/users",
            json={
                "username": "newuser",
                "password": "newpass123",
                "role": "viewer",
                "full_name": "New User",
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 201
        assert r.json()["username"] == "newuser"
        assert r.json()["role"] == "viewer"

        new_token = _login(auth_client, "newuser", "newpass123")
        assert new_token

    def test_create_duplicate_user(self, auth_client):
        admin_token = _login(auth_client)

        r = auth_client.post(
            "/api/v1/auth/users",
            json={"username": "admin", "password": "pass123", "role": "viewer"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 409

    def test_delete_user(self, auth_client):
        admin_token = _login(auth_client)

        auth_client.post(
            "/api/v1/auth/users",
            json={"username": "todelete", "password": "pass123", "role": "viewer"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        r = auth_client.delete(
            "/api/v1/auth/users/todelete",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
        assert r.json()["deleted"] is True

    def test_cannot_delete_self(self, auth_client):
        admin_token = _login(auth_client)

        r = auth_client.delete(
            "/api/v1/auth/users/admin",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 400

    def test_change_own_password(self, auth_client):
        viewer_token = _login(auth_client, "viewer", "viewer123")

        r = auth_client.put(
            "/api/v1/auth/me/password",
            json={"current_password": "viewer123", "new_password": "newviewer123"},
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert r.status_code == 200

        new_token = _login(auth_client, "viewer", "newviewer123")
        assert new_token

        auth_client.put(
            "/api/v1/auth/me/password",
            json={"current_password": "newviewer123", "new_password": "viewer123"},
            headers={"Authorization": f"Bearer {new_token}"},
        )


class TestPublicEndpoints:
    def test_health_no_auth(self, auth_client):
        r = auth_client.get("/api/v1/health")
        assert r.status_code == 200

    def test_ready_no_auth(self, auth_client):
        r = auth_client.get("/api/v1/ready")
        assert r.status_code in (200, 503)

    def test_metrics_no_auth(self, auth_client):
        r = auth_client.get("/api/v1/metrics")
        assert r.status_code == 200

    def test_login_page_served(self, auth_client):
        r = auth_client.get("/login")
        assert r.status_code == 200
        assert "NetSentry" in r.text
