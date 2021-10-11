from typing import Optional

from pydantic import BaseModel, Field


class Login(BaseModel):
    """Login request."""

    username: str
    server_id: str = Field(alias='serverId')
    password: Optional[str]
