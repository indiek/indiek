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

from indiek.core.canonical import DEFAULT_HASH_ALG, DEFAULT_SIG_ALG

# Format 3.0: whole-event signatures, compact canonical JSON,
# algorithm-prefixed digests and signatures.  See :mod:`indiek.core.canonical`
# and :mod:`indiek.core.signing`.  Format 3.1 adds content-less edges
# (``resource_type: "none"``); writers stamp 3.1 only on the events that use
# them, so archives without such edges stay readable by 3.0-only readers.
EVENT_FORMAT_VERSION: str = "3.0"
CONTENTLESS_FORMAT_VERSION: str = "3.1"
FORMAT_VERSION: str = CONTENTLESS_FORMAT_VERSION  # latest format this package reads
SUPPORTED_FORMAT_VERSIONS: frozenset[str] = frozenset(
    {EVENT_FORMAT_VERSION, CONTENTLESS_FORMAT_VERSION}
)
CONTENTLESS_BODY_TYPES: frozenset[str] = frozenset({"edge", "supersede_edge"})

TRANSCRIPTION_EVENT = "transcription"

# ``<alg>:<lowercase hex>``; the algorithm and length are checked on
# verification by :func:`indiek.core.canonical.parse_digest`.
DigestStr = Annotated[str, Field(pattern=r"^[a-z0-9-]+:[0-9a-f]+$")]
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
    NONE = "none"  # no content; edges only, format 3.1


class EventType(str, Enum):
    """Base-network event actions."""

    CREATE_NODE = "create_node"
    CREATE_EDGE = "create_edge"
    SUPERSEDE_NODE = "supersede_node"
    SUPERSEDE_EDGE = "supersede_edge"
    TRANSCRIPTION = TRANSCRIPTION_EVENT


class MetaEventType(str, Enum):
    """Actions in IndieK's tag meta-network."""

    CREATE_EDGE_TAG = "create_edge_tag"
    CREATE_NODE_TAG = "create_node_tag"
    CREATE_EDGE_REPRESENTATION = "create_edge_representation"
    CREATE_NODE_REPRESENTATION = "create_node_representation"
    SET_EDGE_TAG = "set_edge_tag"
    SET_NODE_TAG = "set_node_tag"
    TRANSCRIPTION = TRANSCRIPTION_EVENT


class EventHeader(BaseModel):
    """Signed event-chain metadata."""

    version: str = EVENT_FORMAT_VERSION
    hash_alg: str = DEFAULT_HASH_ALG
    sig_alg: str = DEFAULT_SIG_ALG
    prev_hash: DigestStr | None
    timestamp: dt = Field(default_factory=lambda: dt.now(datetime.UTC))
    author: PublicKeyHexStr


class MetaEventHeader(EventHeader):
    """Header of a meta event: :class:`EventHeader` plus the base anchor.

    ``base_seq`` is the number of base events the author had verified when
    writing the meta event, ``base_head`` the hash of base event number
    ``base_seq`` (``None`` exactly when ``base_seq`` is 0).  Meta commits to
    base; base never commits to meta.
    """

    base_head: DigestStr | None
    base_seq: int = Field(ge=0)

    @model_validator(mode="after")
    def anchor_is_consistent(self) -> "MetaEventHeader":
        """``base_head`` is null exactly when ``base_seq`` is 0."""
        if (self.base_seq == 0) != (self.base_head is None):
            raise ValueError("base_head must be null exactly when base_seq is 0")
        return self


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
        if self.resource_type is ResourceType.NONE:
            if getattr(self, "body_type", None) not in CONTENTLESS_BODY_TYPES:
                raise ValueError("none resources: only edges may have no content")
            if any(
                value is not None
                for value in (
                    self.media_type,
                    self.blob_hash,
                    self.uri,
                    self.path,
                    self.file_size,
                    self.file_hash,
                    self.last_verified,
                )
            ):
                raise ValueError("none resources cannot include any resource field")
        elif self.resource_type is ResourceType.MANAGED:
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


class Transcription(BaseModel):
    """An attestation, signed under the event's own algorithms: "I verified
    this log up to ``verified_head`` (its first ``verified_count`` events)
    under ``verified_hash_alg`` / ``verified_sig_alg`` at ``verified_at``".

    Allowed in the base and in the meta log; it attests only the log it sits
    in, allocates no alias and changes no projection.
    """

    body_type: Literal["transcription"] = "transcription"
    event_type: Literal["transcription"] = "transcription"
    verified_head: DigestStr
    verified_count: int = Field(ge=1)
    verified_hash_alg: str
    verified_sig_alg: str
    verified_at: dt = Field(default_factory=lambda: dt.now(datetime.UTC))
    note: str | None = None


class LogTip(BaseModel):
    """Tip of an event log as recorded in a seal: hash of event number
    ``count`` (``None`` exactly when ``count`` is 0)."""

    head: DigestStr | None
    count: int = Field(ge=0)

    @model_validator(mode="after")
    def tip_is_consistent(self) -> "LogTip":
        if (self.count == 0) != (self.head is None):
            raise ValueError("head must be null exactly when count is 0")
        return self


class SealModel(BaseModel):
    """One line of ``seals/seals.ndjson``: a signed checkpoint of the whole
    archive (base tip, meta tip, blob-store Merkle root).

    ``sig`` covers the canonical bytes of the seal without ``sig``; the seal
    hash is the digest of the whole seal (``sig`` included) and the next
    seal's ``prev_seal_hash``.  Only the first seal has a null
    ``prev_seal_hash``; ``seq`` is the seal's 1-based position.
    """

    type: Literal["seal"] = "seal"
    version: str = EVENT_FORMAT_VERSION
    seq: int = Field(ge=1)
    prev_seal_hash: DigestStr | None
    base: LogTip
    meta: LogTip
    blob_root: DigestStr
    time: dt = Field(default_factory=lambda: dt.now(datetime.UTC))
    hash_alg: str = DEFAULT_HASH_ALG
    sig_alg: str = DEFAULT_SIG_ALG
    key: PublicKeyHexStr
    sig: str | None = None


class EventModel(BaseModel):
    """A complete signed base-network log entry."""

    header: EventHeader
    body: Node | Edge | SupersedeNode | SupersedeEdge | Transcription = Field(
        discriminator="body_type"
    )
    signature: str | None = None

    @model_validator(mode="after")
    def content_less_needs_3_1(self) -> "EventModel":
        """A ``resource_type: "none"`` body is valid only in a 3.1 event."""
        if getattr(self.body, "resource_type", None) is ResourceType.NONE:
            if self.header.version != CONTENTLESS_FORMAT_VERSION:
                raise ValueError(
                    "resource_type 'none' requires format version "
                    f"{CONTENTLESS_FORMAT_VERSION}"
                )
        return self


class MetaEventModel(BaseModel):
    """A complete signed meta-network log entry."""

    header: MetaEventHeader
    body: MetaRepresentation | Tag | MetaEdge | Transcription = Field(
        discriminator="body_type"
    )
    signature: str | None = None
