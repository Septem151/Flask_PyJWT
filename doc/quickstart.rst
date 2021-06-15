Quickstart
==========

To quickly get up and running with Flask_PyJWT, follow the steps in :ref:`Initial Setup`.

For common use cases, see the sections for :ref:`Creating JWTs`, :ref:`Requiring JWTs`, 
:ref:`Route Variable Rules`, :ref:`Requiring Authorization`, :ref:`Using the Current Token`,
and :ref:`Overriding Required Authorization`.

.. _Initial Setup:

Initial Setup
-------------

To start, you will need a flask application::

    # file: app.py

    from flask import Flask

    app = Flask(__name__)

Add some configuration variables to the flask app with a ``.env`` file.
Here's an example ``.env`` file:

.. code-block:: none

    FLASK_ENV="development"
    JWT_ISSUER="Flask_PyJWT"
    JWT_AUTHTYPE="HS256"
    JWT_SECRET="SuperSecretKey"
    # Optional:
    # JWT_AUTHMAXAGE=3600
    # JWT_REFRESHMAXAGE=604800
    # JWT_PUBLICKEY="-----BEGIN PUBLIC KEY-----..."

Alternatively, you can set these configuration variables in code::

    app.config["JWT_ISSUER"] = "Flask_PyJWT"
    app.config["JWT_AUTHTYPE"] = "HS256"
    app.config["JWT_SECRET"] = "SuperSecretKey"
    # Optional:
    # app.config["JWT_AUTHMAXAGE"] = 3600
    # app.config["JWT_REFRESH_MAXAGE"] = 604800
    # app.config["JWT_PUBLICKEY"] = b"-----BEGIN PUBLIC KEY-----..."

For a detailed description of valid configurations, see the :doc:`configuration` section.

Next, we'll add the :class:`~flask_pyjwt.manager.AuthManager` to handle JWTs::

    # file: app.py

    from flask import Flask
    from flask_pyjwt import AuthManager

    app = Flask(__name__)
    auth_manager = AuthManager(app)

.. _Creating JWTs:

Creating JWTs
-------------

The :class:`~flask_pyjwt.manager.AuthManager` is all we need to create new JWTs::

    # file: app.py

    from flask import Flask, request
    from flask_pyjwt import AuthManager

    app = Flask(__name__)
    auth_manager = AuthManager(app)

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

The client can then store the auth and refresh token accordingly.

.. _Requiring JWTs:

Requiring JWTs
--------------

The :class:`~flask_pyjwt.utils.require_token` decorator is used to require the presence
of JWTs in a request. For this example, we'll be expecting an auth token in the 
``Authorization`` header, which is the default setting for :class:`~flask_pyjwt.utils.require_token`::

    # file: app.py

    from flask import Flask
    from flask_pyjwt import AuthManager, require_token

    app = Flask(__name__)
    auth_manager = AuthManager(app)
    
    @app.route("/protected_route")
    @require_token()
    def protected_route():
        return {"message": "You've reached the protected route!"}

.. _Route Variable Rules:

Route Variable Rules
--------------------

To make sure that only certain users can access specific routes, we can use the route's 
variable rules::

    # file: app.py

    from flask import Flask
    from flask_pyjwt import AuthManager, require_token

    app = Flask(__name__)
    auth_manager = AuthManager(app)
    
    @app.route("/user_specific_route/<string:username>")
    @require_token(sub="username")
    def user_specific_route(username):
        return {"message": f"Hello, {username}!"}

Notice how the claim's key is set to the value of the route's variable rule. This lets
Flask_PyJWT know to use the ``username`` value passed in from the URL.

.. note::
   You can require the presence of arbitrary claims on the JWT in the same way. For
   example, to require the presence of a claim named "test" with a value of "test value",
   you would write ``@require_token(test="test value")``. If the "test" claim is not present,
   a 403 Forbidden response is returned.

.. _Requiring Authorization:

Requiring Authorization
-----------------------

To require specific authorization for routes, such as accessing an admin-only URL, 
we can use the ``scope`` parameter. Although other custom claims can be used for authorization
purposes (and return 403 Forbidden responses when not present), it is best practice to
put authorizations in the ``scope`` claim::

    # file: app.py

    from flask import Flask
    from flask_pyjwt import AuthManager, require_token

    app = Flask(__name__)
    auth_manager = AuthManager(app)
    
    @app.route("/admin_dashboard")
    @require_token(scope={"admin": True})
    def admin_dashboard():
        return {"message": f"Hello admin!"}

.. _Using the Current Token:

Using the Current Token
-----------------------

If you need access to the current token being used in the request, use the 
:data:`~flask_pyjwt.utils.current_token` proxy::

    # file: app.py

    from flask import Flask
    from flask_pyjwt import AuthManager, current_token, require_token

    app = Flask(__name__)
    auth_manager = AuthManager(app)
    
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

.. _Overriding Required Authorization:

Overriding Required Authorization
---------------------------------

If you want to add some optional claims that take precedence over required claims,
you can use the ``override`` parameter of the :class:`~flask_pyjwt.utils.require_token`
decorator. This is useful for restricting routes to only authorized users, but also
allowing those with special privileges to be able to access the same restricted routes::

    # file: app.py

    from flask import Flask
    from flask_pyjwt import AuthManager, current_token, require_token

    @app.route("/overridable_route/<string:username>")
    @require_token(sub="username", override={"admin": True})
    def overridable_route():
        is_admin = current_token.claims.get("admin")
        return {"message": f"Hello, {'admin' if is_admin else username}!"}, 200
