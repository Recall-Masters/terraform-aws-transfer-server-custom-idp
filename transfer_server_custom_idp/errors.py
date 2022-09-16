from dataclasses import dataclass
from documented import DocumentedError


@dataclass
class UserNotFound(DocumentedError):
    """SFTP user {self.username} was not found in Secrets Manager."""

    username: str


class IncorrectPassword(DocumentedError):
    """Provided password is incorrect."""

class IncorrectUserConfiguration(DocumentedError):
    """Both `company_id` and `dealer_id` are not provided."""

@dataclass
class MissingCredentials(DocumentedError):
    """Neither `password` nor `key` are provided."""
