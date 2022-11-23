import re
import typing as t
from copy import deepcopy
from functools import wraps
from http import HTTPStatus

from flask import abort, current_app
from flask import g as request_ctx
from flask import request
from flask.ctx import has_request_context
from werkzeug.local import LocalProxy

from .jwt import JWT
from .manager import AuthManager
from .typing import TokenType

AUTH_HEADER_RE = re.compile(r"^Bearer {1}\S*$", re.IGNORECASE)


def is_valid_auth_header(auth_header: str) -> bool:
    """Checks if an ``Authorization`` header follows
    the format "Bearer [token]" (not case sensitive).

    Args:
        auth_header (:obj:`str`): The ``Authorization`` header value.

    Returns:
        :obj:`bool`: True if the ``Authorization`` header is formatted correctly,
        otherwise False.
    """
    return bool(AUTH_HEADER_RE.match(auth_header))


def require_token(
    token_type: t.Literal["auth", "refresh"] = "auth",
    location: t.Literal["header", "cookies"] = "header",
    cookie_name: t.Optional[str] = None,
    scope: t.Optional[t.Union[str, int, dict]] = None,
    override: t.Optional[dict] = None,
    **kwargs,
):
    """Decorator function for requiring an auth or refresh token in either the
    header or cookies of a request.

    Optionally, required claims in the ``scope`` can be checked for authorization.
    Additional ``kwargs`` can be supplied for checking the presence of other claims.
    Route variable rules can be used in the decorator by passing an argument with the
    name of the claim you want equal to the variable rule, and the value of the argument
    being equal to the name of the variable rule.

    Note:
        This decorator must be put **AFTER** the flask app's ``route`` decorator.

    Args:
        token_type (:obj:`str`): Type of token to require ("auth" or "refresh").
            Defaults to "auth".
        location (:obj:`str`): Location of the token in the request
            ("header" or "cookies"). Defaults to "header".
        cookie_name (:obj:`str`): Name of the auth/refresh token cookie.
            Required if the ``location`` is set to "cookies". Defaults to ``None``.
        scope (:obj:`str` | :obj:`int` | :obj:`dict`): Optional claims to check
            in the token's ``scope`` for authorization. Defaults to ``None``.
        override (:obj:`dict`): Optional claims to check for authorization.
            If ``override`` is set, and the claims in ``override`` are present and
            valid, the ``scope`` and additional ``**kwargs`` parameter(s) is ignored.
            Defaults to ``None``.
        **kwargs: Additional claims that must be present on the token for authorization.

    Raises:
        :class:`ValueError`: If ``token_type`` or ``location`` is not a valid value.
        :class:`AttributeError`: If ``cookie_name`` is not present when
            ``location == "cookies"``

    Usage::

        @app.route("/user/<string:user_id>", methods=["POST"])
        @require_token(
            "auth",
            "cookies",
            cookie_name="auth_token",
            sub="user_id",
            custom_claim="Flask_PyJWT",
            override={"admin": True}
        )
        def post_user(user_id: str):
            # If a cookie called "auth_token" in the request
            # does not have a valid auth token, aborts with 401 Unauthorized.
            # If the token's scope contains "admin": True, auth token is valid.
            # Otherwise if the token doesn't have a "sub" claim of user_id
            # or "custom_claim" of "FlaskPyJWT", abort with 403 Forbidden.
            # ... some code to modify the user with id of user_id ...
            return ...

    """
    if token_type not in ("auth", "refresh"):
        raise ValueError("Invalid token type")
    if location not in ("header", "cookies"):
        raise ValueError("Invalid location for auth token")
    if location == "cookies":
        if not cookie_name:
            raise AttributeError('cookie_name must be set when location is "cookies"')

    def decorator(func):
        @wraps(func)
        def wrapper(*a, **k):
            required_claim_keys = deepcopy(kwargs)
            if location == "header":
                auth_header = request.headers.get("Authorization")
                if not auth_header or not is_valid_auth_header(auth_header):
                    abort(
                        HTTPStatus.UNAUTHORIZED,
                        "Improperly formatted or missing Authorization header",
                    )
                jwt_token = auth_header[7:]
            else:
                jwt_token = request.cookies.get(cookie_name)  # type: ignore
                if not jwt_token:
                    abort(HTTPStatus.UNAUTHORIZED, f"Missing {token_type} cookie")
            auth_manager: AuthManager = current_app.extensions["pyjwt_authmanager"]
            is_valid_token = auth_manager.verify_token(jwt_token)
            if not is_valid_token:
                abort(HTTPStatus.UNAUTHORIZED, f"{token_type} token is not valid")
            jwt = auth_manager.convert_token(jwt_token)
            if jwt.token_type != TokenType[token_type.upper()]:
                abort(
                    HTTPStatus.UNAUTHORIZED, f"Invalid token type of {jwt.token_type}"
                )
            if override and _check_claims(override, jwt.claims):
                _add_jwt_to_request_ctx(jwt)
                return func(*a, **k)
            required_claims = {}
            for key, val in k.items():
                if key in required_claim_keys.values():
                    claim_key = list(required_claim_keys.keys())[
                        list(required_claim_keys.values()).index(key)
                    ]
                    required_claims[claim_key] = val
                    required_claim_keys.pop(claim_key)
            for key, val in required_claim_keys.items():
                required_claims[key] = val
            if required_claims and not _check_claims(required_claims, jwt.claims):
                abort(HTTPStatus.FORBIDDEN, "Missing required claim(s)")
            if scope and not _check_claims(scope, jwt.claims.get("scope")):
                abort(HTTPStatus.FORBIDDEN, "Missing required scope(s)")
            _add_jwt_to_request_ctx(jwt)
            return func(*a, **k)

        return wrapper

    return decorator


def _check_claims(
    required_claims: t.Union[str, int, dict],
    jwt_claims: t.Optional[t.Union[str, int, dict]],
) -> bool:
    """Checks a token's claims and/or scope for the presence of the ``required_claims``
    values.

    Args:
        required_claims (:obj:`str` | :obj:`int` | :obj:`dict`): The required claims
            or scopes.
        jwt_claims (:obj:`str` | :obj:`int` | :obj:`dict`): The token's claims
            or scopes.

    Returns:
        :obj:`bool`: True if the token's claims has all required claims,
        otherwise False.
    """
    if isinstance(required_claims, dict):
        for claim, claim_value in required_claims.items():
            if not isinstance(jwt_claims, dict) or claim not in jwt_claims:
                return False
            jwt_claim = jwt_claims[claim]
            if isinstance(jwt_claim, dict) and isinstance(claim_value, dict):
                return _check_claims(claim_value, jwt_claim)
            if isinstance(jwt_claim, (list, set)):
                if not isinstance(claim_value, (list, set)) or not set(
                    claim_value
                ).issubset(jwt_claim):
                    return False
            elif claim_value != jwt_claim:
                return False
    elif required_claims != jwt_claims:
        return False
    return True


def _add_jwt_to_request_ctx(jwt_token: JWT) -> None:
    """Adds a :class:`~flask_pyjwt.jwt.JWT` object to the current request's context.

    Args:
        jwt_token (:class:`~flask_pyjwt.jwt.JWT`): Token to add to the request's
            context.
    """
    request_ctx._flask_pyjwt_jwt_token = jwt_token  # pylint: disable=protected-access


def _get_jwt() -> t.Optional[JWT]:
    """Returns the :class:`~flask_pyjwt.jwt.JWT` object from the current request's
    context.

    Returns:
        The :class:`~flask_pyjwt.jwt.JWT` object from the request's context,
        or ``None`` if there is no request context or the request context has no
        ``jwt_token`` attribute.
    """
    if has_request_context():
        jwt_token: JWT = request_ctx.get("_flask_pyjwt_jwt_token", None)
        return jwt_token
    return None


current_token: JWT = LocalProxy(_get_jwt)  # type: ignore[assignment]
"""A proxy for the current request context's JWT.

Usage::

    @app.route("/protected_route")
    @require_token("auth", "header")
    def protected_route():
        # return the current token that was validated with require_token
        return {"token": current_token.signed}

"""
