###########
Flask_PyJWT
###########

Flast_PyJWT is a flask extension for adding authentication and authorization via
JWT tokens. Routes can be decorated to require JWT auth or refresh tokens, and can
require the presence of additional claims and their values.

************
Installation
************

Flask_PyJWT can be installed with ``pip``:

.. code-block:: console

    pip install Flask_PyJWT

A python version of 3.8 or higher is officially supported. Other versions of Python 3.x
may work, but have not been tested.

Currently, only Flask 1.1.x is officially supported. Flask 2.x *may* work, but has not
been tested.

*************
Documentation
*************

Documentation is hosted by `Read the Docs <https://readthedocs.org/>`_.

You can find documentation for Flask_PyJWT at `<https://flask-pyjwt.readthedocs.io/>`_

*************
Configuration
*************

Flask_PyJWT's configuration variables are read from the Flask app's config and start
with the prefix "JWT\_".

Required Values
===============

JWT_ISSUER
----------

(``str``): The issuer of JWTs. Usually your website/API's name.

JWT_AUTHTYPE
------------

(``str``): The type of auth to use for your JWTs (HMACSHA256, HMACSHA512, RSA256, RSA512).

Accepted Values:

* HS256
* HS512
* RS256
* RS512

JWT_SECRET
----------

(``str`` | ``bytes``): The secret key or RSA private key to sign JWTs with.

If the ``JWT_AUTHTYPE`` is HS256 or HS512, a ``str`` is required.
if the ``JWT_AUTHTYPE`` is RS256 or RS512, a ``bytes`` encoded RSA private key is required.

Optional Values
===============

JWT_AUTHMAXAGE
--------------

(``int``): The maximum time, in seconds, that an auth JWT is considered valid.

JWT_REFRESHMAXAGE
-----------------
(``int``): The maximum time, in seconds, that a refresh JWT is considered valid.

*************
Example Usage
*************

.. code-block:: python

    from Flask import flask, request
    from Flask_PyJWT import auth_manager, current_token, require_token

    app = Flask(__name__)
    app.config["JWT_ISSUER"] = "Flask_PyJWT" # Issuer of tokens
    app.config["JWT_AUTHTYPE"] = "HS256" # HS256, HS512, RS256, or RS512
    app.config["JWT_SECRET"] = "SECRETKEY" # string for HS256/HS512, bytes (RSA Private Key) for RS256/RS512
    app.config["JWT_AUTHMAXAGE"] = 3600
    app.config["JWT_REFRESHMAXAGE"] = 604800

    auth_manager = AuthManager(app)

    # Create auth and refresh tokens with the auth_manager object
    @app.route("/login", METHODS=["POST"])
    def post_token():
        username = request.form["username"]
        password = request.form["password"]
        # Some user authentication via username/password
        if not valid_login(username, password):
            return {"error": "Invalid login credentials"}, 401
        # Retrieve some authorizations the user has, such as {"admin": True}
        authorizations = get_user_authorizations(username)
        # Create the auth and refresh tokens
        auth_token = auth_manager.auth_token(username, authorizations)
        refresh_token = auth_manager.refresh_token(username)
        return {
            "auth_token": auth_token.signed, 
            "refresh_token": refresh_token.signed
        }, 200
    
    # Protect routes by requiring auth tokens
    @app.route("/protected_route")
    @require_token()
    def protected_route():
        return {"message": "You've reached the protected route!"}, 200
    
    # Provision new auth tokens by requiring refresh tokens
    @app.route("/refresh", method=["POST"])
    @require_token("refresh")
    def refresh_token_route():
        username = current_token.sub
        # Retrieve some authorizations the user has, such as {"admin": True}
        authorizations = get_user_authorizations(username)
        new_auth_token = auth_manager.auth_token(username, authorizations)
        return {
            "auth_token": new_auth_token.signed
        }, 200
    
    # Require specific claims in auth or refresh tokens
    # to match a route's rule variables
    @app.route("/user_specific_route/<string:username>")
    @require_token(sub="username")
    def user_specific_route(username):
        return {"message": f"Hello, {username}!"}, 200
    
    # Require arbitrary claims in auth or refresh tokens
    @app.route("/custom_claim_route")
    @require_token(custom_claim="Arbitrary Required Value")
    def custom_claim_route():
        return {"message": "You've reached the custom claim route!"}, 200
    
    # Require authorizations to be present in an auth token's scope
    @app.route("/admin_dashboard")
    @require_token(scope={"admin": True})
    def admin_dashboard():
        return {"message": f"Hello admin!"}
    
    # Access the current token's information using current_token
    @app.route("/token/info")
    @require_token()
    def extract_token_info():
        return {
            "token_type": current_token.token_type,
            "subject": current_token.sub,
            "scope": current_token.scope,
            "claims": current_token.claims,
            "is_signed": current_token.is_signed()
            "signed_token": current_token.signed,
        }
