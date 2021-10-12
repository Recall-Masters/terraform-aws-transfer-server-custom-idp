from dataclasses import dataclass
from documented import DocumentedError


@dataclass
class UserNotFound(DocumentedError):
    """SFTP user {self.username} was not found in Secrets Manager."""

    username: str


class IncorrectPassword(DocumentedError):
    """Provided password is incorrect."""


@dataclass
class MissingCredentials(DocumentedError):
    """Neither `password` nor `key` are provided."""
