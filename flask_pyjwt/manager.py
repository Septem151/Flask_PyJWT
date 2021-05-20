"""Auth Management functions and classes.
"""

from functools import wraps
from typing import Optional, Union

import jwt as PyJWT

from .errors import InvalidConfigError, MissingConfigError, MissingSignerError
from .jwt import JWT, AuthData, AuthType, ClaimsDict, TokenType


def _requires_signer(func):
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
    """[summary]

    Raises:
        :class:`MissingSignerError`: If the :class:`AuthManager` attempts
            to perform a signing or verifying operation without a ``signer``
            present.
    """

    default_auth_max_age = 3600
    default_refresh_max_age = 604800

    def __init__(self, signer: Optional[AuthData] = None) -> None:
        self.signer = signer

    def init_app(self, flask_app) -> None:
        """Initializes the ``signer`` values to config values set in a flask app.

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

        Args:
            flask_app: A flask application to retrieve config values from.

        Raises:
            :class:`MissingConfigError`: If a required config key is missing
                from the flask app.
            :class:`InvalidConfigError`: If a config key's value is of the
                wrong type or an unacceptable value.
        """
        req_configs = ("JWT_ISSUER", "JWT_AUTHTYPE", "JWT_SECRET")
        for config_value in req_configs:
            if not flask_app.config.get(config_value):
                raise MissingConfigError(config_value)
        try:
            auth_type = AuthType[flask_app.config["JWT_AUTHTYPE"]]
        except KeyError as error:
            raise InvalidConfigError("JWT_AUTHTYPE", "Invalid auth type") from error
        secret = flask_app.config["JWT_SECRET"]
        if not isinstance(secret, auth_type.secret_type):
            raise InvalidConfigError("JWT_SECRET", "Secret is of the wrong type")
        issuer = flask_app.config["JWT_ISSUER"]
        if not isinstance(issuer, str):
            raise InvalidConfigError("JWT_ISSUER", "Issuer must be a str")
        auth_max_age = flask_app.config.get(
            "JWT_AUTHMAXAGE", AuthManager.default_auth_max_age
        )
        if not isinstance(auth_max_age, int):
            raise InvalidConfigError("JWT_AUTHMAXAGE", "Auth Max Age must be an int")
        refresh_max_age = flask_app.config.get(
            "JWT_REFRESHMAXAGE", AuthManager.default_refresh_max_age
        )
        if not isinstance(refresh_max_age, int):
            raise InvalidConfigError(
                "JWT_REFRESHMAXAGE", "Refresh Max Age must be an int"
            )
        self.signer = AuthData(auth_type, secret, issuer, auth_max_age, refresh_max_age)

    @_requires_signer
    def auth_token(
        self,
        subject: Union[str, int],
        scope: Optional[Union[str, ClaimsDict]] = None,
        **kwargs: Optional[Union[str, int, ClaimsDict]],
    ) -> JWT:
        auth_token = JWT(TokenType.AUTH, subject, scope, **kwargs)
        assert self.signer is not None
        auth_token.sign(self.signer)
        return auth_token

    @_requires_signer
    def refresh_token(
        self,
        subject: Union[str, int],
    ) -> JWT:
        if self.signer is None:
            raise MissingSignerError()
        refresh_token = JWT(TokenType.REFRESH, subject, None)
        refresh_token.sign(self.signer)
        return refresh_token

    @_requires_signer
    def verify_token(self, token: Union[JWT, str]) -> bool:
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
        return JWT.from_signed_token(signed_token)
