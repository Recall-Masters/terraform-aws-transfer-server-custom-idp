from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


@dataclass
class Secret:
    """Secret model for SFTP user."""

    user_name: str
    home_directory_details: bool
    password: Optional[str] = None
    dealer_id: Optional[str] = None
    type: Optional[str] = None
    company_id: Optional[str] = None
    policy: Optional[Any] = None
    role: Optional[Any] = None
    key: Optional[Any] = None

    def update(self, secret_dict: Dict[str, Any]):
        """Sets additional class attributes based on secret configuration dict."""
        for dict_key, dict_value in secret_dict.items():
            if hasattr(self, dict_key.lower()):
                setattr(self, dict_key.lower(), dict_value)
        return self


class Login(BaseModel):
    """Login request."""

    username: str
    server_id: str = Field(alias="serverId")
    password: Optional[str]


class AWSTransferResponse(BaseModel):
    """Authentication response."""

    public_keys: Optional[List[str]] = Field(None, alias="PublicKeys")

    class Config:
        """Allow sane initialization."""

        allow_population_by_field_name = True
