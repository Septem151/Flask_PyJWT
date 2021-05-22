import typing as t
from enum import Enum, unique

ClaimsDict = t.Dict[  # type: ignore
    str, t.Optional[t.Union[int, str, list, set, bool, "ClaimsDict"]]  # type: ignore
]


class AuthTypeMixin(t.NamedTuple):
    """Mixin class for the :class:`AuthType` enum.

    Contains valid type definitions for a secret key used in signing a JWT.

    Args:
        secret_key (:obj:`type`): The type definition for a secret key.

    Example:
        >>> AuthTypeMixin(str)
        AuthTypeMixin(secret_type=<class 'str'>)

    """

    secret_type: t.Union[t.Type[str], t.Type[bytes]]


class AuthType(AuthTypeMixin, Enum):
    """Enum of values for valid JWT auth types.

    Auth types determine how the JWT signature is created.

    Tokens signed using HMAC can only be verified by those
    that have the secret key.

    Tokens signed using RSA can only be verified by those
    that have the RSA public key associated with the signer's
    private key.

    Attributes:
        name (:obj:`str`): Name of the enum value, this is placed inside of the JWT.
        secret_type (:obj:`type`): Type of secret key that needs to be used,
            whether it's a ``bytes`` key or ``str``. See :class:`AuthTypeMixin`

    Examples:
        >>> AuthType.RS256.name
        'RS256'

        >>> AuthType.RS256.secret_type
        <class 'bytes'>

    """

    RS256 = AuthTypeMixin(bytes)
    RS512 = AuthTypeMixin(bytes)
    HS256 = AuthTypeMixin(str)
    HS512 = AuthTypeMixin(str)


@unique
class TokenType(Enum):
    """Enum of values for valid JWT types.

    Token types include "auth" and "refresh".
    Auth tokens are used for short-term access to resources,
    and Refresh tokens are used for requesting new Auth tokens.

    Attributes:
        name (:obj:`str`): Name of the enum value.
        value (:obj:`str`): Value that is placed inside the JWT.

    Examples:
        >>> TokenType.AUTH.name
        'AUTH'

        >>> TokenType.AUTH.value
        'auth'

    """

    AUTH = "auth"
    REFRESH = "refresh"
