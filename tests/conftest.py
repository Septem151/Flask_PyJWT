import pytest
from flask import Flask
from flask import request as flask_request

from flask_pyjwt import AuthManager, current_token, require_token

from .config import app_configs, test_claims, test_override, test_scope


@pytest.fixture(
    name="flask_app",
    params=app_configs,
)
def fixture_flask_app(request):  # pylint: disable=too-many-locals
    """PyTest Fixture of a Flask App."""
    app = Flask(__name__)
    app.config["TESTING"] = True
    param: dict = request.param
    for config_key, config_value in param.items():
        app.config[config_key] = config_value
    auth_manager = AuthManager(app)

    @app.route("/token", methods=["POST"])
    def auth_token_route():
        json_data: dict = flask_request.get_json()
        sub = json_data.pop("sub")
        scope = json_data.pop("scope", None)
        auth_token = auth_manager.auth_token(sub, scope, **json_data)
        return {
            "token": auth_token.signed,
            "sub": auth_token.sub,
            "scope": auth_token.scope,
            "claims": auth_token.claims,
        }

    @app.route("/refresh", methods=["POST"])
    def refresh_token_route():
        json_data: dict = flask_request.get_json()
        sub = json_data["sub"]
        refresh_token = auth_manager.refresh_token(sub)
        return {
            "token": refresh_token.signed,
            "sub": refresh_token.sub,
            "rid": refresh_token.claims.get("rid"),
        }

    @app.route("/require_auth_header", methods=["GET"])
    @require_token(token_type="auth", location="header")
    def require_auth_token_header_route():
        return {
            "token": current_token.signed,
            "sub": current_token.sub,
            "scope": current_token.scope,
            "claims": current_token.claims,
        }

    @app.route("/require_refresh_header", methods=["GET"])
    @require_token(token_type="refresh", location="header")
    def require_refresh_token_header_route():
        return {
            "token": current_token.signed,
            "sub": current_token.sub,
            "rid": current_token.claims.get("rid"),
        }

    @app.route("/require_auth_cookie", methods=["GET"])
    @require_token(token_type="auth", location="cookies", cookie_name="auth_token")
    def require_auth_token_cookie_route():
        return {
            "token": current_token.signed,
            "sub": current_token.sub,
            "scope": current_token.scope,
            "claims": current_token.claims,
        }

    @app.route("/require_refresh_cookie", methods=["GET"])
    @require_token(
        token_type="refresh", location="cookies", cookie_name="refresh_token"
    )
    def require_refresh_token_cookie_route():
        return {
            "token": current_token.signed,
            "sub": current_token.sub,
            "rid": current_token.claims.get("rid"),
        }

    @app.route("/require_auth_has_scope", methods=["GET"])
    @require_token("auth", "header", scope=test_scope)
    def require_auth_has_scope_route():
        return {
            "token": current_token.signed,
            "sub": current_token.sub,
            "scope": current_token.scope,
            "claims": current_token.claims,
        }

    @app.route("/require_auth_has_claims", methods=["GET"])
    @require_token("auth", "header", **test_claims)
    def require_auth_has_claims_route():
        return {
            "token": current_token.signed,
            "sub": current_token.sub,
            "scope": current_token.scope,
            "claims": current_token.claims,
        }

    @app.route("/require_auth_has_claims/<string:sub>", methods=["GET"])
    @require_token("auth", "header", sub="sub")
    def require_auth_has_claims_in_route_params(sub: str):
        return {
            "token": current_token.signed,
            "sub": current_token.sub,
            "scope": current_token.scope,
            "claims": current_token.claims,
            "route_param": sub,
        }

    @app.route("/require_auth_with_override", methods=["GET"])
    @require_token("auth", "header", scope=test_scope, override=test_override)
    def require_auth_with_override():
        return {
            "token": current_token.signed,
            "sub": current_token.sub,
            "scope": current_token.scope,
            "claims": current_token.claims,
        }

    yield app


@pytest.fixture(name="flask_client")
def fixture_flask_client(flask_app: Flask):
    """PyTest Fixture of a client that uses the Flask App Fixture."""
    with flask_app.test_client() as client:
        yield client
