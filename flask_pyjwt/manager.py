import typing as t
from functools import wraps

import jwt as PyJWT
from flask import Flask

from .errors import InvalidConfigError, MissingConfigError, MissingSignerError
from .jwt import JWT, AuthData
from .typing import AuthType, ClaimsDict, TokenType


def _requires_signer(func):
    """Decorator for requiring the ``signer`` attribute to be set on a given
    :class:`AuthManager` object.

    Raises:
        :class:`~flask_pyjwt.errors.MissingSignerError`: If the :class:`AuthManager`
            attempts to perform a signing or verifying operation without a ``signer``
            present.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        auth_manager: "AuthManager" = args[0]
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
    :meth:`init_app` method on an existing :class:`AuthManager` object, or by
    passing the Flask app directly into the constructor.

    Required config values are:
        * ``JWT_ISSUER`` (:obj:`str`): The issuer of JWTs created by this
            auth manager.
        * ``JWT_AUTHTYPE`` (:obj:`str`): The type of auth to use (ex: ``HS256``)
            for keys created by this auth manager.
        * ``JWT_SECRET`` (:obj:`str` or :obj:`bytes`): The secret key used for
            signing JWTs created by this auth manager.

    Optional config values include:
    * ``JWT_AUTHMAXAGE`` (:obj:`int`): How long auth JWTs created by this
        auth manager are valid for.
    * ``JWT_REFRESHMAXAGE`` (:obj:`int`): How long refresh JWTs created
        by this auth manager are valid for.

    Initializing::

        >>> app = Flask(__name__)
        >>> auth_manager = AuthManager(app)
        >>> # or alternatively:
        >>> auth_manager = AuthManager()
        >>> auth_manager.init_app(app)

    Example Usage::

        >>> @app.route("/token/<str:user_id>", methods=["POST"])
        >>> def index(user_id: str):
        >>>     auth_token = auth_manager.auth_token(
        >>>         subject=user_id,
        >>>         scope={"admin": True},
        >>>         custom_claim="Flask_PyJWT"
        >>>     )
        >>>     return {"auth_token": auth_token.signed}

    Args:
        app (:class:`~flask.Flask`): A flask application to retrieve config values from.

    Raises:
        :class:`~flask_pyjwt.errors.MissingConfigError`: If a required config
            key is missing from the flask app.
        :class:`~flask_pyjwt.errors.InvalidConfigError`: If a config key's value
            is of the wrong type or an unacceptable value.
    """

    default_auth_max_age = 3600
    """:obj:`int`: The default max age for an ``auth`` token.
    """

    default_refresh_max_age = 604800
    """:obj:`int`: The default max age for a ``refresh`` token.
    """

    def __init__(self, app: t.Optional[Flask] = None) -> None:
        if app is not None:
            self.app = app
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        """Initializes this :class:`AuthManager` with the config values in ``app``,
        and attaches itself to the flask app.

        Args:
            app (:class:`~flask.Flask`): A flask application to retrieve config
                values from.

        Raises:
            :class:`~flask_pyjwt.errors.MissingConfigError`: If a required config
                key is missing from the flask app.
            :class:`~flask_pyjwt.errors.InvalidConfigError`: If a config key's value
                is of the wrong type or an unacceptable value.
        """
        req_configs = ("JWT_ISSUER", "JWT_AUTHTYPE", "JWT_SECRET")
        for config_value in req_configs:
            if not app.config.get(config_value):
                raise MissingConfigError(config_value)
        try:
            auth_type = AuthType[app.config["JWT_AUTHTYPE"]]
        except KeyError as error:
            raise InvalidConfigError("JWT_AUTHTYPE", "Invalid auth type") from error
        secret = app.config["JWT_SECRET"]
        if not isinstance(secret, auth_type.secret_type):
            raise InvalidConfigError("JWT_SECRET", "Secret is of the wrong type")
        issuer = app.config["JWT_ISSUER"]
        if not isinstance(issuer, str):
            raise InvalidConfigError("JWT_ISSUER", "Issuer must be a str")
        auth_max_age = app.config.get(
            "JWT_AUTHMAXAGE", AuthManager.default_auth_max_age
        )
        if not isinstance(auth_max_age, int):
            raise InvalidConfigError("JWT_AUTHMAXAGE", "Auth Max Age must be an int")
        refresh_max_age = app.config.get(
            "JWT_REFRESHMAXAGE", AuthManager.default_refresh_max_age
        )
        if not isinstance(refresh_max_age, int):
            raise InvalidConfigError(
                "JWT_REFRESHMAXAGE", "Refresh Max Age must be an int"
            )
        self.signer = AuthData(auth_type, secret, issuer, auth_max_age, refresh_max_age)
        app.auth_manager = self

    @_requires_signer
    def auth_token(
        self,
        subject: t.Union[str, int],
        scope: t.Optional[t.Union[str, ClaimsDict]] = None,
        **kwargs: t.Optional[t.Union[str, int, ClaimsDict]],
    ) -> JWT:
        """Generates a new :class:`~flask_pyjwt.jwt.JWT` with the claims provided.

        Args:
            subject: Value for the ``sub`` claim.
            scope: Optional ``scope`` claim for authorizations. Defaults to None.

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
            subject: Value for the ``sub`` claim.

        Returns:
            :class:`~flask_pyjwt.jwt.JWT`: Token with a ``type`` claim of "refresh".

        Example::

            >>> refresh_token = auth_manager.refresh_token(subject="Flask_PyJWT")
            >>> refresh_token.is_signed()
            True

        """
        if self.signer is None:
            raise MissingSignerError()
        refresh_token = JWT(TokenType.REFRESH, subject, None)
        refresh_token.sign(self.signer)
        return refresh_token

    @_requires_signer
    def verify_token(self, token: t.Union[JWT, str]) -> bool:
        """Verifies that a :class:`~flask_pyjwt.jwt.JWT` or encoded JWT has been signed
        by this :class:`AuthManager` and is not in an invalid format or encoding.

        Args:
            token: The JWT to verify.

        Returns:
            bool: True if the JWT has a valid signature, has required claims, and
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
            PyJWT.decode(
                token.signed,
                self.signer.secret,  # type: ignore
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
            signed_token: A properly encoded JWT.

        Returns:
            JWT: The signed and encoded JWT as a :class:`~flask_pyjwt.jwt.JWT` object.

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
