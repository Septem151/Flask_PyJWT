class MissingSignerError(Exception):
    """Raised when the ``signer`` attribute has not
    been set on an :class:`~flask_pyjwt.manager.AuthManager` object.
    """


class MissingConfigError(Exception):
    """Raised when a config value is missing from an
    :class:`~flask_pyjwt.manager.AuthManager` object.

    Args:
        config_value (:obj:`str`): The config value that raised this exception.
    """

    def __init__(self, config_value: str) -> None:
        super().__init__(config_value)
        self.config_value = config_value

    def __str__(self):
        return f'Missing config value "{self.config_value}"'


class InvalidConfigError(Exception):
    """Raised when a config value is of an incorrect type or is a value
    that is not allowed in an :class:`~flask_pyjwt.manager.AuthManager` object.

    Args:
        config_value (:obj:`str`): The config value that raised this exception.
        message (:obj:`str`): A message describing what the valid config values are.
    """

    def __init__(self, config_value: str, message: str) -> None:
        super().__init__(config_value, message)
        self.config_value = config_value
        self.message = message

    def __str__(self):
        return f'Invalid config "{self.config_value}": {self.message}'
