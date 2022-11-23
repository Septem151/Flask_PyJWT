# pylint: disable=useless-import-alias
from importlib import metadata

from .exceptions import InvalidConfigError as InvalidConfigError
from .exceptions import MissingConfigError as MissingConfigError
from .exceptions import MissingSignerError as MissingSignerError
from .jwt import JWT as JWT
from .jwt import AuthData as AuthData
from .manager import AuthManager as AuthManager
from .typing import AuthType as AuthType
from .typing import TokenType as TokenType
from .utils import current_token as current_token
from .utils import require_token as require_token

__version__ = metadata.version("flask_pyjwt")
