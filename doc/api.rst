API
====

.. module:: flask_pyjwt

AuthManager Object
------------------

.. module:: flask_pyjwt.manager

.. autoclass:: AuthManager
   :members:
   :inherited-members:

Route Decorator
----------------

.. module:: flask_pyjwt.utils

.. autodecorator:: require_token

Current Token Proxy
--------------------

.. data:: current_token

   A proxy for the current request context's :class:`~flask_pyjwt.jwt.JWT` object.

   Usage::

      @app.route("/protected_route")
      @require_token("auth", "header")
      def protected_route():
        # return the current token that was validated with require_token
        return {"token": current_token.signed}

JWT Object
-----------

.. module:: flask_pyjwt.jwt

.. autoclass:: JWT
   :members:
   :inherited-members:

AuthData
^^^^^^^^^

.. autoclass:: AuthData
   :members:
   :inherited-members:

TokenType
^^^^^^^^^^

.. module:: flask_pyjwt.typing

.. autoclass:: TokenType
   :members:
   :inherited-members:

AuthType
^^^^^^^^^

.. autoclass:: AuthType
   :members:
   :inherited-members:

Exceptions
----------

.. module:: flask_pyjwt.exceptions

MissingSignerError
^^^^^^^^^^^^^^^^^^

.. autoclass:: MissingSignerError
   :members:

MissingConfigError
^^^^^^^^^^^^^^^^^^

.. autoclass:: MissingConfigError
   :members:

InvalidConfigError
^^^^^^^^^^^^^^^^^^

.. autoclass :: InvalidConfigError
   :members:
