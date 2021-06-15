import typing as t
from pathlib import Path

DOMAIN = "testing.domain"
JWT_ISSUER = "Flask_PyJWT"
RSA_PRIVATE_KEY_FILENAME = "id_rsa-testing"
RSA_PUBLIC_KEY_FILENAME = f"{RSA_PRIVATE_KEY_FILENAME}.pub"

with open(Path(__file__).parent / RSA_PRIVATE_KEY_FILENAME, "rb") as id_rsa:
    JWT_SECRET = id_rsa.read()
with open(Path(__file__).parent / RSA_PUBLIC_KEY_FILENAME, "rb") as id_rsa_pub:
    JWT_PUBLICKEY = id_rsa_pub.read()

app_configs = [
    {
        "SERVER_NAME": DOMAIN,
        "JWT_ISSUER": JWT_ISSUER,
        "JWT_AUTHTYPE": "HS256",
        "JWT_SECRET": "SECRETKEY",
    },
    {
        "SERVER_NAME": DOMAIN,
        "JWT_ISSUER": JWT_ISSUER,
        "JWT_AUTHTYPE": "HS512",
        "JWT_SECRET": "SECRETKEY",
    },
    {
        "SERVER_NAME": DOMAIN,
        "JWT_ISSUER": JWT_ISSUER,
        "JWT_AUTHTYPE": "RS256",
        "JWT_SECRET": JWT_SECRET,
        "JWT_PUBLICKEY": JWT_PUBLICKEY,
    },
    {
        "SERVER_NAME": DOMAIN,
        "JWT_ISSUER": JWT_ISSUER,
        "JWT_AUTHTYPE": "RS512",
        "JWT_SECRET": JWT_SECRET,
        "JWT_PUBLICKEY": JWT_PUBLICKEY,
    },
]

test_scope: t.Dict[str, t.Any] = {
    "claim1": "val",
    "claim2": 42,
    "claim3": True,
    "claim4": ["litem1", "litem2", "litem3"],
    "claim5": {
        "iclaim1": "val",
        "iclaim2": 42,
        "iclaim3": True,
        "iclaim4": ["litem1", "litem2", "litem3"],
    },
}

test_claims: t.Dict[str, t.Any] = {
    "claim1": "val",
    "claim2": 42,
    "claim3": True,
    "claim4": ["litem1", "litem2", "litem3"],
    "claim5": {
        "iclaim1": "val",
        "iclaim2": 42,
        "iclaim3": True,
        "iclaim4": ["litem1", "litem2", "litem3"],
    },
}

test_override: t.Dict[str, t.Any] = {
    "admin": True,
}
