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

In-memory projection of an archive: current state of every item, the
human-friendly alias maps and the tag assignments.

Replay rules (format 3.0):

* Base log: each ``create_node`` / ``create_edge`` allocates the next ``e{n}``
  alias (one counter for nodes and edges).  ``supersede_*`` replaces the
  item's projected body and allocates nothing; it must be signed by the
  item's creator.
* Meta log: every event (tags, representations and tag assignments) allocates
  the next ``m{n}`` alias.
* ``transcription`` events (either log) allocate nothing and change no item;
  they are listed in :attr:`ArchiveIndex.transcriptions` per network.
* The index is a rebuildable view; the logs are the only source of truth."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID

from indiek.core.archive import ArchiveStore
from indiek.core.errors import IntegrityError, UnknownItemError
from indiek.core.models import TRANSCRIPTION_EVENT, EventType, MetaEventType

Network = Literal["base", "meta"]


class ItemKind(StrEnum):
    """What an indexed item is, derived from its creation event type."""

    NODE = "node"
    EDGE = "edge"
    NODE_TAG = "node_tag"
    EDGE_TAG = "edge_tag"
    NODE_REPRESENTATION = "node_representation"
    EDGE_REPRESENTATION = "edge_representation"
    NODE_TAG_ASSIGNMENT = "node_tag_assignment"
    EDGE_TAG_ASSIGNMENT = "edge_tag_assignment"


_KIND_OF_EVENT: dict[str, ItemKind] = {
    EventType.CREATE_NODE.value: ItemKind.NODE,
    EventType.CREATE_EDGE.value: ItemKind.EDGE,
    MetaEventType.CREATE_NODE_TAG.value: ItemKind.NODE_TAG,
    MetaEventType.CREATE_EDGE_TAG.value: ItemKind.EDGE_TAG,
    MetaEventType.CREATE_NODE_REPRESENTATION.value: ItemKind.NODE_REPRESENTATION,
    MetaEventType.CREATE_EDGE_REPRESENTATION.value: ItemKind.EDGE_REPRESENTATION,
    MetaEventType.SET_NODE_TAG.value: ItemKind.NODE_TAG_ASSIGNMENT,
    MetaEventType.SET_EDGE_TAG.value: ItemKind.EDGE_TAG_ASSIGNMENT,
}

_EDGE_KINDS = {
    ItemKind.EDGE,
    ItemKind.NODE_TAG_ASSIGNMENT,
    ItemKind.EDGE_TAG_ASSIGNMENT,
}
_TAG_KINDS = {ItemKind.NODE_TAG, ItemKind.EDGE_TAG}
_REPRESENTATION_KINDS = {ItemKind.NODE_REPRESENTATION, ItemKind.EDGE_REPRESENTATION}
_ASSIGNMENT_KINDS = {ItemKind.NODE_TAG_ASSIGNMENT, ItemKind.EDGE_TAG_ASSIGNMENT}


@dataclass(slots=True)
class IndexedItem:
    """Current projection of one node, edge or meta item.

    ``body`` is the JSON body of the latest event for the item (the creation
    event, or its most recent supersede).  ``tags`` holds the UUIDs of the
    tags assigned to a base-network item.
    """

    id: UUID
    alias: str
    kind: ItemKind
    author: str
    body: dict[str, Any]
    tags: set[UUID] = field(default_factory=set)

    @property
    def is_meta(self) -> bool:
        return self.kind not in {ItemKind.NODE, ItemKind.EDGE}

    @property
    def is_edge(self) -> bool:
        return self.kind in _EDGE_KINDS

    @property
    def is_tag(self) -> bool:
        return self.kind in _TAG_KINDS


@dataclass(frozen=True, slots=True)
class TranscriptionRecord:
    """A ``transcription`` event: who attested, where it sits, what it says.

    ``position`` is the 1-based place of the event in its own log; ``body``
    holds ``verified_head``, ``verified_count``, ``verified_*_alg``,
    ``verified_at`` and ``note``.
    """

    author: str
    position: int
    body: dict[str, Any]


class ArchiveIndex:
    """Replays a verified :class:`ArchiveStore` into a queryable projection."""

    def __init__(self, store: ArchiveStore) -> None:
        self.store = store
        self.items: dict[UUID, IndexedItem] = {}
        self.aliases: dict[str, UUID] = {}
        self._alias_of: dict[UUID, str] = {}
        self._underlying_of: dict[UUID, UUID] = {}
        self._representation_of: dict[UUID, UUID] = {}
        self.transcriptions: dict[Network, list[TranscriptionRecord]] = {
            "base": [],
            "meta": [],
        }
        self._replay_base()
        self._replay_meta()

    # -- queries -----------------------------------------------------------

    @property
    def head(self) -> str | None:
        return self.store.base_head

    @property
    def meta_head(self) -> str | None:
        return self.store.meta_head

    def resolve(self, ref: str | UUID) -> UUID:
        """Turn an alias (``e3``, ``m1``) or UUID string into a UUID.

        Does not check that the UUID belongs to an item; use :meth:`get`.
        """
        if isinstance(ref, UUID):
            return ref
        if ref in self.aliases:
            return self.aliases[ref]
        try:
            return UUID(ref)
        except ValueError:
            raise UnknownItemError(f"Unknown ID or alias {ref!r}") from None

    def get(self, ref: str | UUID) -> IndexedItem:
        """The indexed item for an alias or UUID."""
        item = self.items.get(self.resolve(ref))
        if item is None:
            raise UnknownItemError(f"Unknown ID or alias {str(ref)!r}")
        return item

    def alias_of(self, item_id: UUID) -> str:
        return self._alias_of[item_id]

    def representation_of(self, underlying_id: UUID) -> UUID | None:
        """Meta representation of a base item, if one was created."""
        return self._representation_of.get(underlying_id)

    def underlying_of(self, representation_id: UUID) -> UUID:
        """Base item represented by a meta representation."""
        return self._underlying_of[representation_id]

    # -- replay ------------------------------------------------------------

    def _add(self, alias: str, item: IndexedItem) -> None:
        self.aliases[alias] = item.id
        self._alias_of[item.id] = alias
        self.items[item.id] = item

    def _replay_base(self) -> None:
        count = 0
        for position, event in enumerate(self.store.base_log, start=1):
            body = event["body"]
            event_type = body.get("event_type")
            author = event["header"]["author"]
            if event_type == TRANSCRIPTION_EVENT:
                self._record_transcription("base", position, author, body)
            elif event_type in {
                EventType.CREATE_NODE.value,
                EventType.CREATE_EDGE.value,
            }:
                count += 1
                kind = _KIND_OF_EVENT[event_type]
                item_id = UUID(body["edge_id" if kind is ItemKind.EDGE else "node_id"])
                self._add(
                    f"e{count}",
                    IndexedItem(item_id, f"e{count}", kind, author, dict(body)),
                )
            elif event_type in {
                EventType.SUPERSEDE_NODE.value,
                EventType.SUPERSEDE_EDGE.value,
            }:
                self._apply_supersede(event_type, body, author)

    def _apply_supersede(
        self, event_type: str, body: dict[str, Any], author: str
    ) -> None:
        is_edge = event_type == EventType.SUPERSEDE_EDGE.value
        raw_id = body["edge_id" if is_edge else "node_id"]
        previous = self.items.get(UUID(raw_id))
        if previous is None:
            raise IntegrityError(f"Supersede event references unknown item {raw_id}")
        if previous.is_edge != is_edge:
            raise IntegrityError(f"Supersede event type does not match item {raw_id}")
        # Only the creator may revise an item, so ``previous.author`` is always
        # the creator (owner decision 2026-10-17).
        if author != previous.author:
            raise IntegrityError(f"Supersede by a non-author of item {raw_id}")
        if is_edge:
            for endpoint in ("source_node", "target_node"):
                if str(previous.body.get(endpoint)) != str(body.get(endpoint)):
                    raise IntegrityError(
                        "Supersede edge events cannot change endpoints"
                    )
        previous.author = author
        previous.body = dict(body)

    def _record_transcription(
        self, network: Network, position: int, author: str, body: dict[str, Any]
    ) -> None:
        self.transcriptions[network].append(
            TranscriptionRecord(author, position, dict(body))
        )

    def _replay_meta(self) -> None:
        count = 0
        for position, event in enumerate(self.store.meta_log, start=1):
            body = event["body"]
            if body["event_type"] == TRANSCRIPTION_EVENT:
                self._record_transcription(
                    "meta", position, event["header"]["author"], body
                )
                continue
            kind = _KIND_OF_EVENT.get(body["event_type"])
            if kind is None:
                continue
            count += 1
            item_id = UUID(body["edge_id"] if "edge_id" in body else body["node_id"])
            author = event["header"]["author"]
            self._add(
                f"m{count}", IndexedItem(item_id, f"m{count}", kind, author, dict(body))
            )
            if kind in _REPRESENTATION_KINDS:
                underlying = UUID(body["underlying_id"])
                self._underlying_of[item_id] = underlying
                self._representation_of[underlying] = item_id
            elif kind in _ASSIGNMENT_KINDS:
                underlying = self._underlying_of.get(UUID(body["target_node"]))
                if underlying is None or underlying not in self.items:
                    raise IntegrityError(
                        "Tag assignment references an unknown representation"
                    )
                self.items[underlying].tags.add(UUID(body["source_node"]))
