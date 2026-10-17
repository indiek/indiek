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
from indiek.core.canonical import event_hash
from indiek.core.models import (
    Edge,
    EventBody,
    EventHeader,
    EventModel,
    MediaType,
    MetaEventHeader,
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
from indiek.core.signing import sign_event
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
        self.base_hashes: list[str] = []

    # -- raw appenders -----------------------------------------------------

    def raw_base(self, body: EventBody, author: Author | None = None) -> None:
        signer = author or self.author
        event = EventModel(
            header=EventHeader(prev_hash=self._base_head, author=signer.public_key_hex),
            body=body,
        )
        event.signature = sign_event(event, signer)
        self.base_log.append(event)
        self._base_head = event_hash(json.loads(event.model_dump_json()))
        self.base_hashes.append(self._base_head)

    def raw_meta(
        self,
        body: MetaEventBody,
        author: Author | None = None,
        anchor: tuple[int, str | None] | None = None,
    ) -> None:
        """Append a meta event anchored to the base tip, or to ``anchor``
        (``(base_seq, base_head)``) to craft deliberately wrong anchors."""
        signer = author or self.author
        base_seq, base_head = anchor or (len(self.base_hashes), self._base_head)
        event = MetaEventModel(
            header=MetaEventHeader(
                prev_hash=self._meta_head,
                author=signer.public_key_hex,
                base_seq=base_seq,
                base_head=base_head,
            ),
            body=body,
        )
        event.signature = sign_event(event, signer)
        self.meta_log.append(event)
        self._meta_head = event_hash(json.loads(event.model_dump_json()))

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
