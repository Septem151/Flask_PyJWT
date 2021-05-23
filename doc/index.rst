Welcome to Flask_PyJWT's documentation!
=======================================

`Flask_PyJWT <https://pypi.org/project/flask-pyjwt/>`_ is a flask extension for adding
authentication and authorization via JWT tokens. Routes can be decorated to require JWT
auth or refresh tokens, and can require the presence of additional claims and their values.

.. toctree::
   :maxdepth: 2
   :caption: Contents:
   
   installation
   quickstart
   configuration
   api

Example
-------

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

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
