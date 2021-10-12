from typing import Optional, List

from pydantic import BaseModel, Field


class Login(BaseModel):
    """Login request."""

    username: str
    server_id: str = Field(alias='serverId')
    password: Optional[str]


class AWSTransferResponse(BaseModel):
    """Authentication response."""

    public_keys: Optional[List[str]] = Field(None, alias='PublicKeys')

    class Config:
        """Allow sane initialization."""

        allow_population_by_field_name = True
