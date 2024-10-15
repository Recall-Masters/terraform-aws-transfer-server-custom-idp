class UserNotFound(Exception):
    """SFTP user {self.username} was not found in Secrets Manager."""

    def __init__(self, username: str):
        super().__init__(
            f'SFTP user: "{username}" '
            'was not found in Secrets Manager.',
        )


class IncorrectPassword(Exception):
    """Provided password is incorrect."""
    def __init__(self):
        super().__init__(
            "Provided password is incorrect.",
        )


class IncorrectUserConfiguration(Exception):
    """Both `company_id` and `dealer_id` are not provided."""
    def __init__(self):
        super().__init__(
            "Both `company_id` and `dealer_id` are not provided.",
        )


class MissingCredentials(Exception):
    """Neither `password` nor `key` are provided."""
    def __init__(self):
        super().__init__(
            "Neither `password` nor `key` are provided.",
        )
