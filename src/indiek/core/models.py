"""Copyright 2026 Adrian Ernesto Radillo

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

---

Pydantic models for the versioned IndieK archive event format.

Events are append-only records.  Creation events establish graph identifiers;
supersede events update their current projection while retaining every previous
signed record in the log.
"""

import datetime
from abc import ABC
from datetime import datetime as dt
from enum import Enum
from typing import Annotated, Literal
from uuid import UUID, uuid7

from pydantic import BaseModel, Field, field_validator, model_validator

# Version 2 adds resource references and append-only supersede events.  Readers
# must treat a missing resource_type in a version 1 event as ``managed``.
EVENT_FORMAT_VERSION: str = "2.0"

Sha256HexStr = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
PublicKeyHexStr = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
BlobHashStr = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]


class MediaType(str, Enum):
    """Media types that IndieK considers archival-safe."""

    TEXT_PLAIN = "text/plain; charset=utf-8"
    TEXT_MARKDOWN = "text/markdown; charset=utf-8"
    IMAGE_TIFF = "image/tiff"
    IMAGE_PNG = "image/png"
    IMAGE_JPEG = "image/jpeg"
    APPLICATION_PDF_A = "application/pdf; profile=pdfa"


class ResourceType(str, Enum):
    """Where an event's resource is stored or referenced."""

    MANAGED = "managed"
    URI = "uri"
    LOCAL_FILE = "local_file"


class EventType(str, Enum):
    """Base-network event actions."""

    CREATE_NODE = "create_node"
    CREATE_EDGE = "create_edge"
    SUPERSEDE_NODE = "supersede_node"
    SUPERSEDE_EDGE = "supersede_edge"


class MetaEventType(str, Enum):
    """Actions in IndieK's tag meta-network."""

    CREATE_EDGE_TAG = "create_edge_tag"
    CREATE_NODE_TAG = "create_node_tag"
    CREATE_EDGE_REPRESENTATION = "create_edge_representation"
    CREATE_NODE_REPRESENTATION = "create_node_representation"
    SET_EDGE_TAG = "set_edge_tag"
    SET_NODE_TAG = "set_node_tag"


class EventHeader(BaseModel):
    """Signed event-chain metadata."""

    version: str = EVENT_FORMAT_VERSION
    prev_hash: Sha256HexStr | None
    timestamp: dt = Field(default_factory=lambda: dt.now(datetime.UTC))
    author: PublicKeyHexStr


MetaEventHeader = EventHeader


class MetaEventBody(BaseModel, ABC):
    """Base class for tag-network event bodies."""

    event_type: MetaEventType


class MetaNode(MetaEventBody):
    """A node in the tag meta-network."""

    node_id: UUID = Field(default_factory=uuid7)


class MetaEdge(MetaEventBody):
    """An edge in the tag meta-network."""

    body_type: Literal["edge"] = "edge"
    edge_id: UUID = Field(default_factory=uuid7)
    source_node: UUID
    target_node: UUID


class Tag(MetaNode):
    """A reusable tag definition."""

    body_type: Literal["tag"] = "tag"
    name: str
    description: str


class MetaRepresentation(MetaNode):
    """A meta-node that represents a base graph item."""

    body_type: Literal["representation"] = "representation"
    underlying_id: UUID


class EventBody(BaseModel, ABC):
    """Shared resource metadata for a base-network event.

    ``managed`` resources have immutable content in the archive blob store;
    ``uri`` resources point to an external URL; ``local_file`` resources retain
    a local-path record and verification data without importing the file.
    """

    event_type: EventType
    resource_type: ResourceType = ResourceType.MANAGED
    media_type: MediaType | None = None
    blob_hash: BlobHashStr | None = None
    uri: str | None = None
    path: str | None = None
    file_size: int | None = Field(default=None, ge=0)
    file_hash: BlobHashStr | None = None
    last_verified: dt | None = None
    title: str | None = None

    @field_validator("blob_hash", "file_hash", mode="before")
    @classmethod
    def prepend_blob_prefix(cls, value: str | None) -> str | None:
        """Normalise SHA-256 values to the archive's ``sha256:`` notation."""
        if isinstance(value, str) and value and not value.startswith("sha256:"):
            return f"sha256:{value}"
        return value

    @model_validator(mode="after")
    def validate_resource_fields(self) -> "EventBody":
        """Require the fields appropriate to the selected resource type."""
        if self.resource_type is ResourceType.MANAGED:
            if self.blob_hash is None or self.media_type is None:
                raise ValueError("managed resources require blob_hash and media_type")
            if any(
                value is not None
                for value in (
                    self.uri,
                    self.path,
                    self.file_size,
                    self.file_hash,
                    self.last_verified,
                )
            ):
                raise ValueError(
                    "managed resources cannot include URI or local-file fields"
                )
        elif self.resource_type is ResourceType.URI:
            if not self.uri:
                raise ValueError("uri resources require uri")
            if self.blob_hash is not None:
                raise ValueError("uri resources cannot include blob_hash")
            if any(
                value is not None
                for value in (
                    self.path,
                    self.file_size,
                    self.file_hash,
                    self.last_verified,
                )
            ):
                raise ValueError("uri resources cannot include local-file fields")
        else:
            if (
                not self.path
                or self.file_size is None
                or self.file_hash is None
                or self.last_verified is None
            ):
                raise ValueError(
                    "local_file resources require path, file_size, file_hash, and last_verified"
                )
            if self.media_type is None:
                raise ValueError("local_file resources require media_type")
            if self.blob_hash is not None or self.uri is not None:
                raise ValueError("local_file resources cannot include blob_hash or uri")
        return self


class Node(EventBody):
    """Create a graph node."""

    body_type: Literal["node"] = "node"
    event_type: Literal[EventType.CREATE_NODE] = EventType.CREATE_NODE
    node_id: UUID = Field(default_factory=uuid7)


class Edge(EventBody):
    """Create a directed graph edge."""

    body_type: Literal["edge"] = "edge"
    event_type: Literal[EventType.CREATE_EDGE] = EventType.CREATE_EDGE
    edge_id: UUID = Field(default_factory=uuid7)
    source_node: UUID
    target_node: UUID


class SupersedeNode(EventBody):
    """Append new resource metadata for an existing node identifier."""

    body_type: Literal["supersede_node"] = "supersede_node"
    event_type: Literal[EventType.SUPERSEDE_NODE] = EventType.SUPERSEDE_NODE
    node_id: UUID


class SupersedeEdge(EventBody):
    """Append new resource metadata for an existing edge without changing topology."""

    body_type: Literal["supersede_edge"] = "supersede_edge"
    event_type: Literal[EventType.SUPERSEDE_EDGE] = EventType.SUPERSEDE_EDGE
    edge_id: UUID
    source_node: UUID
    target_node: UUID


class EventModel(BaseModel):
    """A complete signed base-network log entry."""

    header: EventHeader
    body: Node | Edge | SupersedeNode | SupersedeEdge = Field(discriminator="body_type")
    signature: str | None = None


class MetaEventModel(BaseModel):
    """A complete signed meta-network log entry."""

    header: MetaEventHeader
    body: MetaRepresentation | Tag | MetaEdge = Field(discriminator="body_type")
    signature: str | None = None
