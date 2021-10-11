from typing import Optional

from pydantic import BaseModel


class Login(BaseModel):
    """Login request."""

    username: str
    server_id: str
    password: Optional[str] = None
