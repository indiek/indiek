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

Build, sign and append events; shared lookups used by every operation."""

from __future__ import annotations

from uuid import UUID

from indiek.core.author import Author
from indiek.core.errors import UnknownItemError
from indiek.core.index import ArchiveIndex, IndexedItem
from indiek.core.models import (
    EVENT_FORMAT_VERSION,
    Edge,
    EventHeader,
    EventModel,
    MetaEdge,
    MetaEventHeader,
    MetaEventModel,
    MetaRepresentation,
    Node,
    SupersedeEdge,
    SupersedeNode,
    Tag,
)
from indiek.core.signing import sign_body

BaseBody = Node | Edge | SupersedeNode | SupersedeEdge
MetaBody = Tag | MetaRepresentation | MetaEdge


def append_base(index: ArchiveIndex, author: Author, body: BaseBody) -> EventModel:
    """Sign ``body`` and append it to the base log, chained onto its head."""
    store = index.store
    event = EventModel(
        header=EventHeader(
            version=EVENT_FORMAT_VERSION,
            prev_hash=store.base_head if store.base_count else None,
            author=author.public_key_hex,
        ),
        body=body,
    )
    event.signature = sign_body(event.body, author)
    store.base_log.append(event)
    return event


def append_meta(index: ArchiveIndex, author: Author, body: MetaBody) -> MetaEventModel:
    """Sign ``body`` and append it to the meta log, chained onto its head."""
    store = index.store
    event = MetaEventModel(
        header=MetaEventHeader(
            version=EVENT_FORMAT_VERSION,
            prev_hash=store.meta_head if store.meta_count else None,
            author=author.public_key_hex,
        ),
        body=body,
    )
    event.signature = sign_body(event.body, author)
    store.meta_log.append(event)
    return event


def require_base_item(index: ArchiveIndex, ref: str | UUID, *, edge: bool) -> IndexedItem:
    """Look up a base-network node (``edge=False``) or edge (``edge=True``).

    Raises:
        UnknownItemError: ``"<Node|Edge> '<ref>' does not exist in this archive"``
            or ``"ID '<ref>' does not reference a base-network <node|edge>"``.
    """
    label = "Edge" if edge else "Node"
    try:
        item = index.get(ref)
    except UnknownItemError:
        raise UnknownItemError(f"{label} {ref!r} does not exist in this archive") from None
    if item.is_meta or item.is_edge != edge:
        raise UnknownItemError(f"ID {ref!r} does not reference a base-network {label.lower()}")
    return item
