"""JWT-related type and object declarations.
"""
import time
from enum import Enum, unique
from typing import Any, Dict, NamedTuple, Optional, Type, Union

import jwt as PyJWT

ClaimsDict = Dict[  # type: ignore
    str, Optional[Union[int, str, "ClaimsDict", list, set]]  # type: ignore
]


class AuthTypeMixin(NamedTuple):
    """Mixin class for the :class:`AuthType` enum.

    Contains valid type definitions for a secret key used in signing a JWT.

    Args:
        secret_key (type): The type definition for a secret key.

    Example:
        >>> AuthTypeMixin(str)
        AuthTypeMixin(secret_type=<class 'str'>)
    """

    secret_type: Union[Type[str], Type[bytes]]


class AuthType(AuthTypeMixin, Enum):
    """Enum of values for valid JWT auth types.

    Auth types determine how the JWT signature is created.

    Tokens signed using HMAC can only be verified by those
    that have the secret key.

    Tokens signed using RSA can only be verified by those
    that have the RSA public key associated with the signer's
    private key.

    Attributes:
        name (str): Name of the enum value, this is placed inside of the JWT.
        secret_type (type): Type of secret key that needs to be used,
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
        name (str): Name of the enum value.
        value (str): Value that is placed inside the JWT.

    Examples:
        >>> TokenType.AUTH.name
        'AUTH'

        >>> TokenType.AUTH.value
        'auth'
    """

    AUTH = "auth"
    REFRESH = "refresh"


class AuthData:
    """Contains values used for signing a JWT.

    Used as a "signer" object for JWTs.

    Args:
        auth_type: The :class:`AuthType` that should be used when signing a JWT.
        secret: The secret key used to sign a JWT. Must match the type specified
            in the ``auth_type`` parameter's secret_type.
        issuer: Identifier for who will issue a JWT.
        max_age: The maximum of a JWT.

    Attributes:
        auth_type: The :class:`AuthType` that should be used when signing a JWT.
        secret: The secret key used to sign a JWT. Must match the type specified
            in the ``auth_type`` parameter's secret_type.
        issuer: Identifier for who will issue a JWT.
        max_age: The maximum of a JWT.

    Raises:
        TypeError: If the ``secret`` parameter's type does not match the type
            specified in the ``auth_type`` parameter's secret type.
    """

    def __init__(
        self, auth_type: AuthType, secret: Union[bytes, str], issuer: str, max_age: int
    ) -> None:
        if not isinstance(secret, auth_type.secret_type):
            raise TypeError(
                f"'secret' parameter must be of type {auth_type.secret_type}"
            )
        self.auth_type = auth_type
        self.secret = secret
        self.issuer = issuer
        self.max_age = max_age

    def algorithm(self) -> str:
        """Returns the algorithm type used.

        Returns:
            ``name`` attribute of the ``auth_type`` attribute.
        """
        return self.auth_type.name

    def partial_payload(self, current_time: int) -> dict:
        """Returns partial payload claims for a JWT to be signed.

        Args:
            current_time: The current time this JWT will be considered valid.

        Returns::
            {
                "iss": issuer,
                "exp": current_time + max_age
            }
        """
        return {
            "iss": self.issuer,
            "exp": current_time + self.max_age,
        }


class JWT:
    """Representation of a signed JWT."""

    def __init__(
        self,
        token_type: TokenType,
        sub: Union[str, int],
        scope: Optional[Union[str, ClaimsDict]] = None,
        **kwargs: Optional[Union[str, int, ClaimsDict]],
    ) -> None:
        self.token_type = token_type
        self.payload: Dict[str, Any] = {"sub": sub}
        if scope:
            self.payload["scope"] = scope
        for key, value in kwargs.items():
            self.payload[key] = value
        self.signed: Optional[str] = None

    def sign(self, auth_data: AuthData) -> str:
        """Signs this JWT, setting the ``iat`` to be the current time
        when this function is called.

        Args:
            auth_data: The `AuthData` object containing relevant signing information.

        Returns:
            An encoded JWT with valid signature containing all claims
            that this object possesses.
        """
        cur_time = int(time.time())
        signed_payload = {
            **self.payload,
            "iat": cur_time,
            **auth_data.partial_payload(cur_time),
        }
        if self.token_type == TokenType.REFRESH and "scope" in signed_payload:
            signed_payload.pop("scope")
        elif self.token_type == TokenType.AUTH and "rid" in signed_payload:
            signed_payload.pop("rid")
        self.signed = PyJWT.encode(
            signed_payload, auth_data.secret, auth_data.algorithm()  # type: ignore
        )
        return self.signed

    def is_signed(self) -> bool:
        """Returns whether this JWT has been signed.

        Returns:
            True if signed, False if not.
        """
        return self.signed is not None
