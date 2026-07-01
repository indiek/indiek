from pydantic import BaseModel, Field, field_validator
from typing_extensions import Annotated
from uuid import UUID, uuid7
import time
from enum import Enum

# Reusable regex constraint for exactly 64-character lowercase hex strings (SHA-256)
Sha256HexStr = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]

# Reusable regex constraint for modern cryptographic public keys (e.g., 64-char Hex Ed25519)
PublicKeyHexStr = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class MediaType(str, Enum):
    TEXT_PLAIN = "text/plain; charset=utf-8"
    VIDEO_MP4 = "video/mp4"
    IMAGE_JPEG = "image/jpeg"
    IMAGE_PNG = "image/png"
    APPLICATION_OCTET = "application/octet-stream"


class EventHeader(BaseModel):
    version: str = "1.0"
    prev_hash: Sha256HexStr | None  # String and hex validation applied automatically
    timestamp: str = Field(
        default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    )
    author: PublicKeyHexStr


class EventBody(BaseModel):
    event_type: str = "create_node"
    node_id: UUID = Field(default_factory=uuid7)
    media_type: MediaType  # Restricted strictly to Enum items
    blob_hash: str = Field(
        pattern=r"^sha256:[0-9a-f]{64}$"
    )  # Validates after prefix injection

    # 2. Field validator to automatically prepend the prefix 'sha256:'
    @field_validator("blob_hash", mode="before")
    @classmethod
    def prepend_blob_prefix(cls, value: str) -> str:
        if isinstance(value, str) and not value.startswith("sha256:"):
            return f"sha256:{value}"
        return value


class EventModel(BaseModel):
    header: EventHeader
    body: EventBody
