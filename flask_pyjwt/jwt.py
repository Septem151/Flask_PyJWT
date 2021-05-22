import base64
import json
import secrets
import time
import typing as t

from jwt import InvalidKeyError, InvalidTokenError
from jwt import decode as pyjwt_decode
from jwt import encode as pyjwt_encode

from .typing import AuthType, ClaimsDict, TokenType


class AuthData:
    """Contains values used for signing a JWT.

    Used as a "signer" object for JWTs.

    Args:
        auth_type: The :class:`AuthType` that should be used when signing a JWT.
        secret: The secret key used to sign a JWT. Must match the type specified
            in the ``auth_type`` parameter's secret_type.
        issuer: Identifier for who will issue a JWT.
        auth_max_age: The max age for a JWT with :class:`TokenType` of ``AUTH``.
        refresh_max_age: The max age for a JWT with :class:`TokenType` of ``REFRESH``.

    Attributes:
        auth_type: The :class:`AuthType` that should be used when signing a JWT.
        secret: The secret key used to sign a JWT. Must match the type specified
            in the ``auth_type`` parameter's secret_type.
        issuer: Identifier for who will issue a JWT.
        auth_max_age: The max age for a JWT with :class:`TokenType` of ``AUTH``.
        refresh_max_age: The max age for a JWT with :class:`TokenType` of ``REFRESH``.

    Raises:
        TypeError: If the ``secret`` parameter's type does not match the type
            specified in the ``auth_type`` parameter's secret type.

    Example::

        auth_data = AuthData(AuthType.HS256, "SECRETKEY", "Flask_PyJWT", 120, 3600)
        jwt_token = JWT(TokenType.AUTH, "SomeSubjectID")
        signed_token = jwt_token.sign(auth_data)

    """

    def __init__(
        self,
        auth_type: AuthType,
        secret: t.Union[bytes, str],
        issuer: str,
        auth_max_age: int,
        refresh_max_age: int,
    ) -> None:
        if not isinstance(secret, auth_type.secret_type):
            raise TypeError(
                f"'secret' parameter must be of type {auth_type.secret_type}"
            )
        self.auth_type = auth_type
        self.secret = secret
        self.issuer = issuer
        self.auth_max_age = auth_max_age
        self.refresh_max_age = refresh_max_age

    def algorithm(self) -> str:
        """Returns the algorithm type used.

        Returns:
            ``name`` attribute of the ``auth_type`` attribute.
        """
        return self.auth_type.name

    def extend_claims(
        self, token_type: TokenType, claims: t.Dict[str, t.Union[str, int, ClaimsDict]]
    ) -> t.Dict[str, t.Union[str, int, ClaimsDict]]:
        """Returns modified claims for a JWT to be signed.

        Adds an ``iss``, ``iat``, and ``exp`` key to the claims dict.

        Args:
            token_type: The type of token to sign, which determines the ``exp`` value.
            claims (:obj:`dict`): The claims to sign and extend.

        Returns:
            ``rid`` claim is only present if ``token_type`` is ``TokenType.REFRESH``::

            {
                "iss": str,
                "iat": int,
                "exp": int,
                "rid": str
                **claims
            }

        """
        extended_claims: t.Dict[str, t.Union[str, int, ClaimsDict]] = {}
        current_time = int(time.time())
        expiry_time = current_time
        if token_type == TokenType.AUTH:
            expiry_time += self.auth_max_age
        elif token_type == TokenType.REFRESH:
            expiry_time += self.refresh_max_age
            extended_claims["rid"] = secrets.token_urlsafe(16)
        extended_claims.update(iss=self.issuer, iat=current_time, exp=expiry_time)
        extended_claims.update(claims)
        return extended_claims


class JWT:
    """Representation of a JWT.

    Args:
        token_type: Type of JWT, described by a :class:`TokenType`.
        sub: Subject of the JWT.
        scope: Used for declaring authorizations. Defaults to None.
        **kwargs: Any extra claims to add to the JWT.

    Attributes:
        token_type: Type of JWT, described by a :class:`TokenType`.
        claims (:obj:`dict`): The token's claims.
        signed (:obj:`str`, optional): The signed, encoded JWT.

    Example::

        jwt_token = JWT(
            TokenType.AUTH,
            "SomeSubjectID",
            scope={"admin": True},
            extra_key="KeyVal"
        )

    """

    def __init__(
        self,
        token_type: TokenType,
        sub: t.Union[str, int],
        scope: t.Optional[t.Union[str, int, ClaimsDict]] = None,
        **kwargs: t.Optional[t.Union[str, int, ClaimsDict]],
    ) -> None:
        self.token_type = token_type
        self.claims: t.Dict[str, t.Any] = {"sub": sub, "type": token_type.value}
        if scope:
            self.claims["scope"] = scope
        for key, value in kwargs.items():
            self.claims[key] = value
        self.signed: t.Optional[str] = None

    def sign(self, auth_data: AuthData) -> str:
        """Signs this JWT, setting the ``iat`` to be the current time
        when this function is called.

        Args:
            auth_data: The `AuthData` object containing relevant signing information.

        Returns:
            An encoded JWT with valid signature containing all claims
            that this object possesses.
        """
        self.claims = auth_data.extend_claims(self.token_type, self.claims)
        if self.token_type == TokenType.REFRESH and "scope" in self.claims:
            self.claims.pop("scope")
        elif self.token_type == TokenType.AUTH and "rid" in self.claims:
            self.claims.pop("rid")
        self.signed = pyjwt_encode(
            self.claims, auth_data.secret, auth_data.algorithm()  # type: ignore
        )
        return self.signed

    def is_signed(self) -> bool:
        """Returns whether this JWT has been signed.

        Returns:
            True if signed, False if not.
        """
        return self.signed is not None

    @classmethod
    def from_signed_token(cls, signed_token: str) -> "JWT":
        """Converts a signed JWT into a :class:`JWT` object

        Raises:
            ``InvalidTokenError``: If the ``signed_token`` parameter is not
                a valid token or does not contain the required claims
                "exp", "iss", "sub", "iat", and "type".

        Returns:
            :class:`JWT`: A :class:`JWT` object containing the data from the
                ``signed_token`` parameter.
        """
        try:
            header = signed_token.split(".")[0]
            header_bytes = header.encode("ascii")
            rem = len(header_bytes) % 4
            if rem > 0:
                header_bytes += b"=" * (4 - rem)
            decoded_header = base64.urlsafe_b64decode(header_bytes).decode("utf-8")
            header_dict = json.loads(decoded_header)
            if not all(key in header_dict for key in ("alg", "typ")):
                raise InvalidKeyError("alg and typ must be present in header")
        except Exception as error:
            raise InvalidTokenError("Token was in an invalid format") from error
        algorithm = AuthType[header_dict["alg"]]
        claims = pyjwt_decode(
            signed_token,
            algorithms=[algorithm.name],
            options={
                "require": ["exp", "iss", "sub", "iat", "type"],
                "verify_signature": False,
            },
        )
        token_type = TokenType[claims["type"].upper()]
        jwt_token = cls(token_type, **claims)
        jwt_token.signed = signed_token
        return jwt_token
