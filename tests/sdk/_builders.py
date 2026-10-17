"""Test helper: append correctly chained, signed events using ``indiek.core`` only.

Lets SDK tests craft archives (including logically invalid ones that still
pass chain verification) without going through the CLI or ``indiek.ops``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal
from uuid import UUID

from indiek.core.author import Author
from indiek.core.canonical import canonical_hash
from indiek.core.models import (
    Edge,
    EventBody,
    EventHeader,
    EventModel,
    MediaType,
    MetaEdge,
    MetaEventBody,
    MetaEventModel,
    MetaEventType,
    MetaRepresentation,
    Node,
    SupersedeEdge,
    SupersedeNode,
    Tag,
)
from indiek.core.signing import sign_body
from indiek.core.storage import BlobStore, EventLog

Kind = Literal["node", "edge"]


class Builder:
    """Writes base/meta events for ``author`` into the archive at ``root``."""

    def __init__(self, root: Path, author: Author) -> None:
        self.root = root
        self.author = author
        self.blobs = BlobStore(root)
        self.base_log = EventLog(root / "events")
        self.meta_log = EventLog(root / "meta" / "events")
        self._base_head: str | None = None
        self._meta_head: str | None = None

    # -- raw appenders -----------------------------------------------------

    def raw_base(self, body: EventBody, author: Author | None = None) -> None:
        signer = author or self.author
        event = EventModel(
            header=EventHeader(prev_hash=self._base_head, author=signer.public_key_hex),
            body=body,
        )
        event.signature = sign_body(event.body, signer)
        self.base_log.append(event)
        self._base_head = canonical_hash(json.loads(event.model_dump_json())).hex()

    def raw_meta(self, body: MetaEventBody, author: Author | None = None) -> None:
        signer = author or self.author
        event = MetaEventModel(
            header=EventHeader(prev_hash=self._meta_head, author=signer.public_key_hex),
            body=body,
        )
        event.signature = sign_body(event.body, signer)
        self.meta_log.append(event)
        self._meta_head = canonical_hash(json.loads(event.model_dump_json())).hex()

    def _blob(self, text: str) -> str:
        return self.blobs.put(text)

    # -- base network ------------------------------------------------------

    def node(self, text: str, title: str | None = None) -> UUID:
        body = Node(
            blob_hash=self._blob(text), media_type=MediaType.TEXT_PLAIN, title=title
        )
        self.raw_base(body)
        return body.node_id

    def edge(self, source: UUID, target: UUID, text: str) -> UUID:
        body = Edge(
            blob_hash=self._blob(text),
            media_type=MediaType.TEXT_PLAIN,
            source_node=source,
            target_node=target,
        )
        self.raw_base(body)
        return body.edge_id

    def supersede_node(
        self,
        node_id: UUID,
        text: str,
        title: str | None = None,
        author: Author | None = None,
    ) -> None:
        body = SupersedeNode(
            node_id=node_id,
            blob_hash=self._blob(text),
            media_type=MediaType.TEXT_MARKDOWN,
            title=title,
        )
        self.raw_base(body, author)

    def supersede_edge(
        self, edge_id: UUID, source: UUID, target: UUID, text: str
    ) -> None:
        body = SupersedeEdge(
            edge_id=edge_id,
            source_node=source,
            target_node=target,
            blob_hash=self._blob(text),
            media_type=MediaType.TEXT_PLAIN,
        )
        self.raw_base(body)

    # -- meta network ------------------------------------------------------

    def tag(self, name: str, kind: Kind = "node") -> UUID:
        body = Tag(
            name=name,
            description=f"About {name}",
            event_type=MetaEventType(f"create_{kind}_tag"),
        )
        self.raw_meta(body)
        return body.node_id

    def representation(self, underlying: UUID, kind: Kind = "node") -> UUID:
        body = MetaRepresentation(
            underlying_id=underlying,
            event_type=MetaEventType(f"create_{kind}_representation"),
        )
        self.raw_meta(body)
        return body.node_id

    def assign(
        self, tag_id: UUID, representation_id: UUID, kind: Kind = "node"
    ) -> UUID:
        body = MetaEdge(
            source_node=tag_id,
            target_node=representation_id,
            event_type=MetaEventType(f"set_{kind}_tag"),
        )
        self.raw_meta(body)
        return body.edge_id
