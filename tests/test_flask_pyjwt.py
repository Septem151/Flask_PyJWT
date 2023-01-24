import pytest  # pylint: disable=unused-import
from flask import Flask, Response
from flask.testing import FlaskClient

from flask_pyjwt import AuthManager, __version__

from .config import DOMAIN, test_claims, test_override, test_scope


def test_version():
    """Assert that the version of flask_pyjwt matches the expected version."""
    assert __version__ == "0.1.9"


def test_auth_manager_creates_valid_auth_token(
    flask_app: Flask, flask_client: FlaskClient
):
    """Assert that the AuthManager creates valid Auth tokens."""
    resp = flask_client.post(
        "/token",
        json={"sub": "test", "scope": {"admin": True}, "custom_claim": "SomeValue"},
    )
    data: dict = resp.get_json()
    assert "token" in data
    auth_manager: AuthManager = flask_app.auth_manager
    assert auth_manager.verify_token(data["token"])
    assert "sub" in data
    assert data["sub"] == "test"


def test_auth_manager_creates_valid_refresh_token(
    flask_app: Flask, flask_client: FlaskClient
):
    """Asserts that the AuthManager creates valid Refresh tokens."""
    resp: Response = flask_client.post("/refresh", json={"sub": "test"})
    data: dict = resp.get_json()
    assert "token" in data
    auth_manager: AuthManager = flask_app.auth_manager
    assert auth_manager.verify_token(data["token"])
    assert "rid" in data
    assert data["rid"] is not None


def test_require_token_checks_for_auth_token_in_headers(flask_client: FlaskClient):
    """Asserts that the require_token decorator checks for Auth tokens
    in a request's header.
    """
    resp: Response = flask_client.post("/token", json={"sub": "test"})
    data: dict = resp.get_json()
    assert "token" in data
    resp = flask_client.get(
        "/require_auth_header", headers={"Authorization": f"Bearer {data['token']}"}
    )
    data = resp.get_json()
    assert "sub" in data
    assert data["sub"] == "test"


def test_require_token_checks_for_refresh_token_in_headers(flask_client: FlaskClient):
    """Asserts that the require_token decorator checks for Refresh tokens
    in a request's header.
    """
    resp: Response = flask_client.post("/refresh", json={"sub": "test"})
    data: dict = resp.get_json()
    assert "token" in data
    resp = flask_client.get(
        "/require_refresh_header", headers={"Authorization": f"Bearer {data['token']}"}
    )
    data = resp.get_json()
    assert "sub" in data
    assert "rid" in data
    assert data["sub"] == "test"
    assert data["rid"] is not None


def test_require_token_checks_for_auth_token_in_cookies(flask_client: FlaskClient):
    """Asserts that the require_token decorator checks for Auth tokens
    in a request's cookies.
    """
    resp: Response = flask_client.post("/token", json={"sub": "test"})
    data: dict = resp.get_json()
    assert "token" in data
    flask_client.set_cookie(DOMAIN, "auth_token", data["token"])
    resp = flask_client.get("/require_auth_cookie")
    data = resp.get_json()
    assert "sub" in data
    assert data["sub"] == "test"


def test_require_token_checks_for_refresh_token_in_cookies(flask_client: FlaskClient):
    """Asserts that the require_token decorator checks for Refresh tokens
    in a request's cookies.
    """
    resp: Response = flask_client.post("/refresh", json={"sub": "test"})
    data: dict = resp.get_json()
    assert "token" in data
    flask_client.set_cookie(DOMAIN, "refresh_token", data["token"])
    resp = flask_client.get("/require_refresh_cookie")
    data = resp.get_json()
    assert "sub" in data
    assert "rid" in data
    assert data["sub"] == "test"
    assert data["rid"] is not None


def test_require_token_accepts_present_required_scope(flask_client: FlaskClient):
    """Asserts that the require_token decorator accepts requests when the
    request's Auth token has required scope values.
    """
    resp: Response = flask_client.post(
        "/token", json={"sub": "test", "scope": test_scope}
    )
    data: dict = resp.get_json()
    assert "token" in data
    resp = flask_client.get(
        "/require_auth_has_scope", headers={"Authorization": f"Bearer {data['token']}"}
    )
    data = resp.get_json()
    assert resp.status_code == 200
    assert "sub" in data
    assert "scope" in data
    assert data["sub"] == "test"
    assert data["scope"] == test_scope


def test_require_token_rejects_missing_required_scope(flask_client: FlaskClient):
    """Asserts that the require_token decorator rejects requests when the
    request's Auth token is missing required scope values.
    """
    resp: Response = flask_client.post("/token", json={"sub": "test"})
    data: dict = resp.get_json()
    assert "token" in data
    resp = flask_client.get(
        "/require_auth_has_scope", headers={"Authorization": f"Bearer {data['token']}"}
    )
    assert resp.status_code == 403


def test_require_token_accepts_present_required_claims(flask_client: FlaskClient):
    """Asserts that the require_token decorator accepts requests when the
    request's Auth token has required additional claims.
    """
    resp: Response = flask_client.post("/token", json={"sub": "test", **test_claims})
    data: dict = resp.get_json()
    assert "token" in data
    resp = flask_client.get(
        "/require_auth_has_claims", headers={"Authorization": f"Bearer {data['token']}"}
    )
    data = resp.get_json()
    assert resp.status_code == 200
    assert "sub" in data
    assert "claims" in data
    assert data["sub"] == "test"
    for claim_key, claim_value in test_claims.items():
        assert data["claims"].get(claim_key) == claim_value


def test_require_token_rejects_missing_required_claims(flask_client: FlaskClient):
    """Asserts that the require_token decorator rejects requests when the
    request's Auth token is missing required additional claims.
    """
    resp: Response = flask_client.post("/token", json={"sub": "test"})
    data: dict = resp.get_json()
    assert "token" in data
    resp = flask_client.get(
        "/require_auth_has_claims", headers={"Authorization": f"Bearer {data['token']}"}
    )
    assert resp.status_code == 403


def test_require_token_accepts_present_required_route_claim(flask_client: FlaskClient):
    """Asserts that the require_token decorator accepts requests when the
    request's Auth token has required claims that are part of a Route's parameters.
    """
    resp: Response = flask_client.post("/token", json={"sub": "test"})
    data: dict = resp.get_json()
    assert "token" in data
    resp = flask_client.get(
        "/require_auth_has_claims/test",
        headers={"Authorization": f"Bearer {data['token']}"},
    )
    data = resp.get_json()
    assert resp.status_code == 200
    assert "sub" in data
    assert "claims" in data
    assert "route_param" in data
    assert data["sub"] == "test"
    assert data["route_param"] == "test"


def test_require_token_rejects_invalid_required_route_claim(flask_client: FlaskClient):
    """Asserts that the require_token decorator rejects requests when the request's
    Auth token is missing required claims that are part of a Route's parameters.
    """
    resp: Response = flask_client.post("/token", json={"sub": "not_test"})
    data: dict = resp.get_json()
    assert "token" in data
    resp = flask_client.get(
        "/require_auth_has_claims/test",
        headers={"Authorization": f"Bearer {data['token']}"},
    )
    assert resp.status_code == 403


def test_require_token_accepts_present_required_scope_and_missing_override(
    flask_client: FlaskClient,
):
    """Asserts that the require_token decorator accepts requests when the request's
    Auth token has required scope and the decorator has an override set.
    """
    resp: Response = flask_client.post(
        "/token", json={"sub": "test", "scope": test_scope}
    )
    data: dict = resp.get_json()
    assert "token" in data
    resp = flask_client.get(
        "/require_auth_with_override",
        headers={"Authorization": f"Bearer {data['token']}"},
    )
    data = resp.get_json()
    assert resp.status_code == 200
    assert "sub" in data
    assert "scope" in data
    assert data["sub"] == "test"
    assert data["scope"] == test_scope


def test_require_token_accepts_missing_required_scope_and_present_override(
    flask_client: FlaskClient,
):
    """Asserts that the require_token decorator accepts requests when the request's
    Auth token is missing required scope but has optional override claims when the
    decorator has an override set.
    """
    resp: Response = flask_client.post("/token", json={"sub": "test", **test_override})
    data: dict = resp.get_json()
    assert "token" in data
    resp = flask_client.get(
        "/require_auth_with_override",
        headers={"Authorization": f"Bearer {data['token']}"},
    )
    data = resp.get_json()
    assert resp.status_code == 200
    assert "sub" in data
    assert "scope" in data
    assert data["sub"] == "test"
    for claim_key, claim_value in test_override.items():
        assert data["claims"].get(claim_key) == claim_value


def test_require_token_rejects_missing_required_scope_and_missing_override(
    flask_client: FlaskClient,
):
    """Asserts that the require_token decorator rejects requests when the request's
    Auth token is missing required scope and missing optional override claims when
    the decorator has an override set.
    """
    resp: Response = flask_client.post(
        "/token", json={"sub": "test", "scope": {"admin": False}}
    )
    data: dict = resp.get_json()
    assert "token" in data
    resp = flask_client.get(
        "/require_auth_with_override",
        headers={"Authorization": f"Bearer {data['token']}"},
    )
    assert resp.status_code == 403
