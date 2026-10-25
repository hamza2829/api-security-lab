"""Regression tests reuse the four original attack functions."""

import time
from pathlib import Path

import jwt
import pytest

from app_fixed.config import load_jwt_secret
from exploits import exposed_secret, forge_jwt, idor, sql_injection


@pytest.fixture(scope="module")
def fixed_api(start_server):
    return start_server("app_fixed")


def test_idor_is_blocked(fixed_api):
    assert not idor.exploit(fixed_api)


def test_sql_injection_is_blocked(fixed_api):
    assert not sql_injection.exploit(fixed_api)


def test_forged_jwt_is_blocked(fixed_api):
    assert not forge_jwt.exploit(fixed_api)


def test_committed_key_is_removed():
    assert not exposed_secret.exploit(Path(__file__).resolve().parents[1] / "app_fixed")


def test_correctly_signed_expired_token_is_rejected(fixed_api, signing_secret):
    # A weak-key forgery alone would not prove that expiry is checked.
    token = jwt.encode({"sub": "3", "exp": 1}, signing_secret, algorithm="HS256")
    response = fixed_api.get("/admin/users", headers={"Authorization": "Bearer " + token})
    assert response.status_code == 401


def test_missing_expiry_is_rejected(fixed_api, signing_secret):
    token = jwt.encode({"sub": "3"}, signing_secret, algorithm="HS256")
    response = fixed_api.get("/admin/users", headers={"Authorization": "Bearer " + token})
    assert response.status_code == 401


def test_future_token_signed_with_weak_key_is_rejected(fixed_api):
    # Separate key verification from expiry verification.
    token = jwt.encode(
        {"sub": "3", "exp": int(time.time()) + 3600}, "secret123", algorithm="HS256"
    )
    response = fixed_api.get("/admin/users", headers={"Authorization": "Bearer " + token})
    assert response.status_code == 401


def test_owner_can_still_read_and_search(fixed_api):
    headers = fixed_api.login()
    response = fixed_api.get("/notes/1", headers=headers)
    assert response.status_code == 200
    assert response.json()["owner_id"] == 1
    response = fixed_api.get("/search", params={"q": "Alice"}, headers=headers)
    assert response.status_code == 200
    assert [row["id"] for row in response.json()] == [1]


def test_empty_search_stays_within_owner(fixed_api):
    response = fixed_api.get("/search", headers=fixed_api.login())
    assert response.status_code == 200
    assert [row["id"] for row in response.json()] == [1]


def test_admin_check_and_admin_login_still_work(fixed_api):
    response = fixed_api.get("/admin/users", headers=fixed_api.login())
    assert response.status_code == 403
    response = fixed_api.get("/admin/users", headers=fixed_api.login("admin"))
    assert response.status_code == 200
    assert len(response.json()) == 3


@pytest.mark.parametrize("path", ["/notes/1", "/search", "/admin/users"])
def test_authentication_is_required(fixed_api, path):
    assert fixed_api.get(path).status_code == 401


@pytest.mark.parametrize("secret", [None, "secret123"])
def test_missing_or_short_secret_fails_closed(monkeypatch, secret):
    if secret is None:
        monkeypatch.delenv("LAB_JWT_SECRET", raising=False)
    else:
        monkeypatch.setenv("LAB_JWT_SECRET", secret)
    with pytest.raises(RuntimeError, match="LAB_JWT_SECRET"):
        load_jwt_secret()


def test_search_treats_apostrophe_as_data(fixed_api):
    response = fixed_api.get("/search", params={"q": "'"}, headers=fixed_api.login())
    assert response.status_code == 200
    assert response.json() == []
