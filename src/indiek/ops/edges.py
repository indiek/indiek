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

Create directed edges, with ``text/plain`` content or none, and supersede
edge content."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from indiek.core.author import Author
from indiek.core.errors import AuthorshipError, UnknownItemError
from indiek.core.index import ArchiveIndex, ItemKind
from indiek.core.models import Edge, MediaType, ResourceType, SupersedeEdge
from indiek.core.storage import BLOB_HASH_PREFIX
from indiek.ops.events import append_base, require_base_item


def _require_node(index: ArchiveIndex, node_id: UUID, role: str) -> None:
    item = index.items.get(node_id)
    if item is None or item.kind is not ItemKind.NODE:
        raise UnknownItemError(f"{role} NODE {node_id} NOT FOUND IN ARCHIVE")


def _resource(index: ArchiveIndex, content: str | None) -> dict[str, Any]:
    """Resource fields of an edge body; stores ``content`` as a blob if given."""
    if content is None:
        return {"resource_type": ResourceType.NONE}
    digest = index.store.blobs.put(content)
    return {
        "resource_type": ResourceType.MANAGED,
        "media_type": MediaType.TEXT_PLAIN,
        "blob_hash": BLOB_HASH_PREFIX + digest,
    }


def create_edge(
    index: ArchiveIndex,
    author: Author,
    source: str | UUID,
    target: str | UUID,
    content: str | None = None,
) -> UUID:
    """Append a directed edge from ``source`` to ``target`` carrying ``content``.

    ``content`` is always stored verbatim as ``text/plain`` (a file path is
    not read); ``None`` makes a content-less edge (``resource_type: "none"``,
    format 3.1, no blob).  Endpoints must be existing base-network nodes; they are
    validated before anything is written.

    Raises:
        UnknownItemError: unknown alias, or an endpoint that is not a node.
    """
    source_id, target_id = index.resolve(source), index.resolve(target)
    _require_node(index, source_id, "SOURCE")
    _require_node(index, target_id, "TARGET")
    body = Edge(
        source_node=source_id, target_node=target_id, **_resource(index, content)
    )
    append_base(index, author, body)
    return body.edge_id


def supersede_edge(
    index: ArchiveIndex,
    author: Author,
    ref: str | UUID,
    content: str | None = None,
) -> UUID:
    """Append replacement ``text/plain`` content for an existing edge, or
    make it content-less (``content=None``).

    Endpoints and title are copied from the current projection; they can
    never change.

    Raises:
        AuthorshipError: ``author`` did not create the edge (checked before
            anything is written).
    """
    item = require_base_item(index, ref, edge=True)
    if author.public_key_hex != item.author:
        raise AuthorshipError(f"Only the author of Edge {ref!r} may supersede it")
    body = SupersedeEdge(
        edge_id=item.id,
        source_node=UUID(str(item.body["source_node"])),
        target_node=UUID(str(item.body["target_node"])),
        title=item.body.get("title"),
        **_resource(index, content),
    )
    append_base(index, author, body)
    return item.id
