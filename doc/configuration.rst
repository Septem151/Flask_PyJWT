Configuration
=============

Flask_PyJWT's configuration variables are read from the Flask app's config and start
with the prefix "JWT\_".

Required Values
---------------

JWT_ISSUER
^^^^^^^^^^

(:obj:`str`): The issuer of JWTs. Usually your website/API's name.

JWT_AUTHTYPE
^^^^^^^^^^^^

(:obj:`str`): The type of auth to use for your JWTs
(HMACSHA256, HMACSHA512, RSA256, RSA512).

Accepted Values:

* HS256
* HS512
* RS256
* RS512

JWT_SECRET
^^^^^^^^^^

(:obj:`str` | :obj:`bytes`): The secret key or RSA private key to sign JWTs with.

If the ``JWT_AUTHTYPE`` is HS256 or HS512, a :obj:`str` is required.
if the ``JWT_AUTHTYPE`` is RS256 or RS512, a :obj:`bytes` encoded RSA private key is required.

Optional Values
---------------

JWT_AUTHMAXAGE
^^^^^^^^^^^^^^

(:obj:`int`): The maximum time, in seconds, that an auth JWT is considered valid.

JWT_REFRESHMAXAGE
^^^^^^^^^^^^^^^^^

(:obj:`int`): The maximum time, in seconds, that a refresh JWT is considered valid.

JWT_PUBLICKEY
^^^^^^^^^^^^^

(:obj:`str` | :obj:`bytes`): The RSA public key used to verify JWTs with, if the ``JWT_AUTHTYPE``
is set to RS256 or RS512.
