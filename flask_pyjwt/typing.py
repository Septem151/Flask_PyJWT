import typing as t
from enum import Enum, unique


class AuthTypeMixin(t.NamedTuple):
    """Mixin class for the :class:`~flask_pyjwt.typing.AuthType` enum.

    Contains valid type definitions for a secret key used in signing a JWT.

    Args:
        algorithm (:obj:`str`): Name of the auth algorithm.
        secret_type (:obj:`type`): Type of secret key that needs to be used,
            whether it's a ``bytes`` key or ``str``.
    """

    algorithm: str
    secret_type: t.Union[t.Type[str], t.Type[bytes]]


class AuthType(AuthTypeMixin, Enum):
    """Auth types determine how the JWT signature is created.

    Tokens signed using HMAC can only be verified by those
    that have the secret key.

    Tokens signed using RSA can only be verified by those
    that have the RSA public key associated with the signer's
    private key.

    Attributes:
        name (:obj:`str`): Name of the enum value, this is placed inside of the JWT.
    """

    RS256 = AuthTypeMixin("RS256", bytes)
    RS512 = AuthTypeMixin("RS512", bytes)
    HS256 = AuthTypeMixin("HS256", str)
    HS512 = AuthTypeMixin("HS512", str)


@unique
class TokenType(Enum):
    """Enum of values for valid JWT types.

    Token types include "auth" and "refresh".
    Auth tokens are used for short-term access to resources,
    and Refresh tokens are used for requesting new Auth tokens.

    Attributes:
        name (:obj:`str`): Name of the enum value.
        value (:obj:`str`): Value that is placed inside the JWT.
    """

    AUTH = "auth"
    REFRESH = "refresh"
