import re
import typing as t
from functools import wraps
from http import HTTPStatus

from flask import abort, current_app, request
from flask.ctx import has_request_context
from flask.globals import _request_ctx_stack
from werkzeug.local import LocalProxy

from .jwt import JWT
from .manager import AuthManager
from .typing import ClaimsDict, TokenType

AUTH_HEADER_RE = re.compile(r"^Bearer {1}\S*$", re.IGNORECASE)


def is_valid_auth_header(auth_header: str) -> bool:
    return bool(AUTH_HEADER_RE.match(auth_header))


def require_token(
    token_type: t.Literal["auth", "refresh"] = "auth",
    location: t.Literal["header", "cookies"] = "header",
    cookie_name: t.Optional[str] = None,
    scope: t.Optional[t.Union[str, int, ClaimsDict]] = None,
):
    if token_type not in ("auth", "refresh"):
        raise ValueError("Invalid token type")
    if location not in ("header", "cookies"):
        raise ValueError("Invalid location for auth token")
    if location == "cookies":
        if not cookie_name:
            raise AttributeError('cookie_name must be set when location is "cookies"')

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if location == "header":
                auth_header = request.headers.get("Authorization")
                if not auth_header or not is_valid_auth_header(auth_header):
                    abort(HTTPStatus.UNAUTHORIZED)
                jwt_token = auth_header[7:]
            else:
                jwt_token = request.cookies.get(cookie_name)
                if not jwt_token:
                    abort(HTTPStatus.UNAUTHORIZED)
            auth_manager: AuthManager = current_app.auth_manager
            is_valid_token = auth_manager.verify_token(jwt_token)
            if not is_valid_token:
                abort(HTTPStatus.UNAUTHORIZED)
            jwt = auth_manager.convert_token(jwt_token)
            if jwt.token_type != TokenType[token_type.upper()]:
                abort(HTTPStatus.UNAUTHORIZED)
            if scope and not _check_scope(scope, jwt.claims.get("scope")):
                abort(HTTPStatus.FORBIDDEN)
            _add_jwt_to_request_ctx(jwt)
            return func(*args, **kwargs)

        return wrapper

    return decorator


def _check_scope(
    required_scopes: t.Union[str, int, ClaimsDict],
    jwt_scopes: t.Optional[t.Union[str, int, ClaimsDict]],
) -> bool:
    if isinstance(required_scopes, dict):
        for scope, scope_value in required_scopes.items():
            if not isinstance(jwt_scopes, dict) or scope not in jwt_scopes:
                return False
            jwt_scope = jwt_scopes[scope]
            if isinstance(jwt_scope, dict) and isinstance(scope_value, dict):
                return _check_scope(scope_value, jwt_scope)
            if isinstance(jwt_scope, (list, set)):
                if not isinstance(scope_value, (list, set)) or not set(
                    scope_value
                ).issubset(jwt_scope):
                    return False
            elif scope_value != jwt_scope:
                return False
    elif required_scopes != jwt_scopes:
        return False
    return True


def _add_jwt_to_request_ctx(jwt_token: JWT) -> None:
    ctx = _request_ctx_stack.top
    ctx.jwt_token = jwt_token


def _get_jwt() -> JWT:
    if has_request_context() and hasattr(_request_ctx_stack.top, "jwt_token"):
        jwt_token: JWT = getattr(_request_ctx_stack.top, "jwt_token")
        return jwt_token
    raise RuntimeError("Missing jwt_token on request context")


current_token: JWT = LocalProxy(_get_jwt)  # type: ignore
