import os
import typing as t
from functools import wraps

import jwt as PyJWT
from dotenv import load_dotenv
from flask import Flask

from .exceptions import InvalidConfigError, MissingConfigError, MissingSignerError
from .jwt import JWT, AuthData
from .typing import AuthType, TokenType


def _requires_signer(func):
    """Decorator for requiring the ``signer`` attribute to be set on a given
    :class:`~flask_pyjwt.manager.AuthManager` object.

    Raises:
        :class:`~flask_pyjwt.exceptions.MissingSignerError`: If the
            :class:`~flask_pyjwt.exceptions.AuthManager` attempts to perform a signing
            or verifying operation without a ``signer`` present.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        auth_manager: AuthManager = args[0]
        if auth_manager.signer is None:
            raise MissingSignerError(
                "AuthManager is missing the required signer attribute"
            )
        return func(*args, **kwargs)

    return wrapper


class AuthManager:
    """The main object used for interfacing with Flask_PyJWT.

    Includes methods for creating auth and refresh tokens, and verifying tokens.
    Can be initialized using the application factory pattern by calling the
    :meth:`init_app` method on an existing :class:`~flask_pyjwt.manager.AuthManager`
    object, or by passing the Flask app directly into the constructor.

    Required config values are:

        * ``JWT_ISSUER`` (:obj:`str`): The issuer of JWTs created by this auth manager.
        * ``JWT_AUTHTYPE`` (:obj:`str`): The type of auth to use (ex: ``HS256``)
            for keys created by this auth manager.
        * ``JWT_SECRET`` (:obj:`str` | :obj:`bytes`): The secret key used for
            signing JWTs created by this auth manager.

    Optional config values include:

        * ``JWT_AUTHMAXAGE`` (:obj:`int`): How long auth JWTs created by this
            auth manager are valid for.
        * ``JWT_REFRESHMAXAGE`` (:obj:`int`): How long refresh JWTs created
            by this auth manager are valid for.
        * ``JWT_PUBLICKEY`` (:obj:`str` | :obj:`bytes`): The public key used for
            verifying signed JWTs created by this auth manager if the RSA algorithm
            is used.

    Initializing::

        app = Flask(__name__)
        auth_manager = AuthManager(app)
        # or alternatively:
        auth_manager = AuthManager()
        auth_manager.init_app(app)

    Example Usage::

        @app.route("/token/<str:user_id>", methods=["POST"])
        def index(user_id: str):
            auth_token = auth_manager.auth_token(
                subject=user_id,
                scope={"admin": True},
                custom_claim="Flask_PyJWT"
            )
            return {"auth_token": auth_token.signed}

    Args:
        app (:class:`~flask.Flask`): A flask application to retrieve config values from.
        dotenv_path (:obj:`str` | ``None``): The absolute or relative path to a .env
            file to load configuration variables from.

    Raises:
        :class:`~flask_pyjwt.exceptions.MissingConfigError`: If a required config
            key is missing from the flask app.
        :class:`~flask_pyjwt.exceptions.InvalidConfigError`: If a config key's value
            is of the wrong type or an unacceptable value.
    """

    default_auth_max_age: int = 3600
    """:obj:`int`: The default max age for an ``auth`` token.
    """

    default_refresh_max_age: int = 604800
    """:obj:`int`: The default max age for a ``refresh`` token.
    """

    def __init__(
        self, app: t.Optional[Flask] = None, dotenv_path: t.Optional[str] = None
    ) -> None:
        load_dotenv(dotenv_path)
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        """Initializes an :class:`~flask_pyjwt.manager.AuthManager` with the config
        values in ``app``, and attaches itself to the flask app.

        Args:
            app (:class:`~flask.Flask`): A flask application to retrieve config
                values from.

        Raises:
            :class:`~flask_pyjwt.exceptions.MissingConfigError`: If a required config
                key is missing from the flask app.
            :class:`~flask_pyjwt.exceptions.InvalidConfigError`: If a config key's value
                is of the wrong type or an unacceptable value.
        """
        cast_required = False
        req_configs = ("JWT_ISSUER", "JWT_AUTHTYPE", "JWT_SECRET")
        for config_value in req_configs:
            if not app.config.get(config_value):
                if config_value == "JWT_SECRET":
                    cast_required = True
                app.config[config_value] = os.environ.get(config_value)
                if not app.config.get(config_value):
                    raise MissingConfigError(config_value)
        try:
            auth_type = AuthType[app.config["JWT_AUTHTYPE"]]
        except KeyError as error:
            raise InvalidConfigError("JWT_AUTHTYPE", "Invalid auth type") from error
        secret = (
            app.config["JWT_SECRET"].encode("utf-8")
            if cast_required and auth_type in (AuthType.RS256, AuthType.RS512)
            else app.config["JWT_SECRET"]
        )
        if not isinstance(secret, auth_type.secret_type):
            raise InvalidConfigError("JWT_SECRET", "Secret is of the wrong type")
        public_key = None
        if auth_type in (AuthType.RS256, AuthType.RS512):
            public_key = app.config.get(
                "JWT_PUBLICKEY", os.environ.get("JWT_PUBLICKEY")
            )
            if not public_key:
                raise MissingConfigError("JWT_PUBLICKEY")
            if not isinstance(public_key, bytes):
                public_key = public_key.encode("utf-8")
        issuer = app.config["JWT_ISSUER"]
        if not isinstance(issuer, str):
            raise InvalidConfigError("JWT_ISSUER", "Issuer must be a str")
        auth_max_age = app.config.get(
            "JWT_AUTHMAXAGE",
            int(os.environ.get("JWT_AUTHMAXAGE", AuthManager.default_auth_max_age)),
        )
        if not isinstance(auth_max_age, int):
            raise InvalidConfigError("JWT_AUTHMAXAGE", "Auth Max Age must be an int")
        refresh_max_age = app.config.get(
            "JWT_REFRESHMAXAGE",
            int(
                os.environ.get("JWT_REFRESHMAXAGE", AuthManager.default_refresh_max_age)
            ),
        )
        if not isinstance(refresh_max_age, int):
            raise InvalidConfigError(
                "JWT_REFRESHMAXAGE", "Refresh Max Age must be an int"
            )
        self.signer = AuthData(
            auth_type, secret, issuer, auth_max_age, refresh_max_age, public_key
        )
        app.extensions["pyjwt_authmanager"] = self

    @_requires_signer
    def auth_token(
        self,
        subject: t.Union[str, int],
        scope: t.Optional[t.Union[str, dict]] = None,
        **kwargs: t.Optional[t.Union[str, int, dict]],
    ) -> JWT:
        """Generates a new :class:`~flask_pyjwt.jwt.JWT` with the claims provided.

        Args:
            subject (:obj:`str` | :obj:`int`): Value for the ``sub`` claim.
            scope (:obj:`str` | :obj:`dict`): Optional ``scope`` claim for
                authorizations. Defaults to ``None``.
            **kwargs: Any additional claims to add to the JWT.

        Returns:
            :class:`~flask_pyjwt.jwt.JWT`: Token with a ``type`` claim of "auth".

        Example::

            >>> auth_token = auth_manager.auth_token(subject="Flask_PyJWT")
            >>> auth_token.is_signed()
            True

        """
        auth_token = JWT(TokenType.AUTH, subject, scope, **kwargs)
        assert self.signer is not None
        auth_token.sign(self.signer)
        return auth_token

    @_requires_signer
    def refresh_token(
        self,
        subject: t.Union[str, int],
    ) -> JWT:
        """Generates a new :class:`~flask_pyjwt.jwt.JWT` with the claims provided.

        Args:
            subject (:obj:`str` | :obj:`int`): Value for the ``sub`` claim.

        Returns:
            :class:`~flask_pyjwt.jwt.JWT`: Token with a ``type`` claim of "refresh".

        Example::

            refresh_token = auth_manager.refresh_token(subject="Flask_PyJWT")

        """
        if self.signer is None:
            raise MissingSignerError()
        refresh_token = JWT(TokenType.REFRESH, subject, None)
        refresh_token.sign(self.signer)
        return refresh_token

    @_requires_signer
    def verify_token(self, token: t.Union[JWT, str]) -> bool:
        """Verifies that a :class:`~flask_pyjwt.jwt.JWT` or encoded JWT has been signed
        by this :class:`~flask_pyjwt.manager.AuthManager` and is not in an invalid
        format or encoding.

        Args:
            token (:class:`~flask_pyjwt.jwt.JWT` | :obj:`str`): The JWT to verify.

        Returns:
            :obj:`bool`: True if the JWT has a valid signature, has required claims, and
            has the required claims of ``iat``, ``exp``, and ``iss``, otherwise
            False.

        Note:
            This function does **NOT** verify additional custom claims nor scope.

        Example::

            >>> auth_token = auth_manager.auth_token(subject="Flask_PyJWT")
            >>> verify_token(auth_token)
            True

        """
        try:
            if not isinstance(token, JWT):
                token = self.convert_token(token)
            if not token.is_signed():
                return False
            assert token.signed is not None
            assert self.signer is not None
            verifier = (
                self.signer.secret
                if not self.signer.public_key
                else self.signer.public_key
            )
            PyJWT.decode(
                token.signed,
                verifier,  # type: ignore
                issuer=self.signer.issuer,
                algorithms=[self.signer.algorithm()],
                options={
                    "require": ["exp", "iss", "sub", "iat"],
                    "verify_iat": True,
                    "verify_exp": True,
                    "verify_iss": True,
                    "verify_signature": True,
                },
            )
        except PyJWT.InvalidTokenError:
            return False
        return True

    @staticmethod
    def convert_token(signed_token: str) -> JWT:
        """Converts a signed encoded JWT into a :class:`~flask_pyjwt.jwt.JWT` object.

        Args:
            signed_token (:obj:`str`): A properly encoded JWT.

        Returns:
            :class:`~flask_pyjwt.jwt.JWT`: The signed and encoded JWT as a
            :class:`~flask_pyjwt.jwt.JWT` object.

        Raises:
            ``InvalidTokenError``: If the ``signed_token`` parameter is not
                a valid token or does not contain the required claims
                "exp", "iss", "sub", "iat", and "type".

        Example::

            >>> signed_encoded_token = "eyJhbG..._adQssw5c"
            >>> jwt = convert_token(signed_encoded_token)
            >>> print(jwt.signed)
            'eyJhbG..._adQssw5c'

        """
        return JWT.from_signed_token(signed_token)
