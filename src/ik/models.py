from pydantic import BaseModel, Field, field_validator
from typing_extensions import Annotated, Literal, Union
from uuid import UUID, uuid7
from datetime import datetime as dt
import datetime
from enum import Enum
from abc import ABC

# Reusable regex constraint for exactly 64-character lowercase hex strings (SHA-256)
Sha256HexStr = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]

# Reusable regex constraint for modern cryptographic public keys (e.g., 64-char Hex Ed25519)
PublicKeyHexStr = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class MediaType(str, Enum):
    TEXT_PLAIN = "text/plain; charset=utf-8"


class EventType(str, Enum):
    CREATE_NODE = "create_node"
    CREATE_EDGE = "create_edge"


class MetaEventType(str, Enum):
    CREATE_EDGE_TAG = "create_edge_tag"  # node in meta network
    CREATE_NODE_TAG = "create_node_tag"  # node in meta network
    CREATE_EDGE_REPRESENTATION = "create_edge_representation"  # node in meta network
    CREATE_NODE_REPRESENTATION = "create_node_representation"  # node in meta network
    SET_EDGE_TAG = "set_edge_tag"  # edge in meta network
    SET_NODE_TAG = "set_node_tag"  # edge in meta network


class EventHeader(BaseModel):
    version: str = "1.0"
    prev_hash: Sha256HexStr | None  # String and hex validation applied automatically
    timestamp: dt = Field(default_factory=lambda: dt.now(datetime.UTC))
    author: PublicKeyHexStr


MetaEventHeader = EventHeader


class MetaEventBody(BaseModel, ABC):
    event_type: MetaEventType


class MetaNode(MetaEventBody):
    # should not be instantiated, only subclassed
    node_id: UUID = Field(default_factory=uuid7)


class Tag(MetaNode):
    body_type: Literal["tag"] = "tag"
    name: str
    description: str


class MetaRepresentation(MetaNode):
    body_type: Literal["representation"] = "representation"
    underlying_id: UUID


class EventBody(BaseModel, ABC):
    event_type: EventType
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


class Node(EventBody):
    body_type: Literal["node"] = "node"
    node_id: UUID = Field(default_factory=uuid7)


class Edge(EventBody):
    body_type: Literal["edge"] = "edge"
    edge_id: UUID = Field(default_factory=uuid7)
    source_node: UUID
    target_node: UUID


class EventModel(BaseModel):
    header: EventHeader
    body: Union[Node, Edge] = Field(discriminator="body_type")
    signature: str | None = None


class MetaEventModel(BaseModel):
    header: MetaEventHeader
    body: Union[MetaRepresentation, Tag] = Field(discriminator="body_type")
    signature: str | None = None
