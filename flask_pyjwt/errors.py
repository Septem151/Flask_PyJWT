class MissingSignerError(Exception):
    pass


class MissingConfigError(Exception):
    def __init__(self, config_value: str) -> None:
        super().__init__(config_value)
        self.config_value = config_value

    def __str__(self):
        return f'Missing config value "{self.config_value}"'


class InvalidConfigError(Exception):
    def __init__(self, config_value: str, message: str) -> None:
        super().__init__(config_value, message)
        self.config_value = config_value
        self.message = message

    def __str__(self):
        return f'Invalid config "{self.config_value}": {self.message}'
