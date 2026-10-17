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

Tags: define node/edge tags and assign them to base-network items.

Assigning a tag writes, in the meta network, a representation of the target
(only the first time that target is tagged) and a meta edge from the tag to
that representation."""

from __future__ import annotations

import logging
from typing import Literal, get_args
from uuid import UUID

from indiek.core.author import Author
from indiek.core.errors import ArchiveRuleError, AuthorshipError, UnknownItemError
from indiek.core.index import ArchiveIndex, IndexedItem, ItemKind
from indiek.core.models import MetaEdge, MetaEventType, MetaRepresentation, Tag
from indiek.ops.events import append_meta

logger = logging.getLogger(__name__)

TagKind = Literal["node", "edge"]

_TAG_EVENT = {
    "node": MetaEventType.CREATE_NODE_TAG,
    "edge": MetaEventType.CREATE_EDGE_TAG,
}


def create_tag(
    index: ArchiveIndex,
    author: Author,
    name: str,
    description: str,
    kind: TagKind,
) -> UUID:
    """Define a tag usable on nodes (``kind="node"``) or edges (``kind="edge"``).

    Names are not unique.  Only ``author`` may later assign the tag.
    """
    if kind not in get_args(TagKind):
        raise ArchiveRuleError(f"Tag kind must be 'node' or 'edge', not {kind!r}")
    body = Tag(name=name, description=description, event_type=_TAG_EVENT[kind])
    append_meta(index, author, body)
    return body.node_id


def _create_representation(index: ArchiveIndex, author: Author, target: IndexedItem) -> UUID:
    event_type = (
        MetaEventType.CREATE_EDGE_REPRESENTATION
        if target.is_edge
        else MetaEventType.CREATE_NODE_REPRESENTATION
    )
    body = MetaRepresentation(event_type=event_type, underlying_id=target.id)
    append_meta(index, author, body)
    return body.node_id


def set_tag(
    index: ArchiveIndex,
    author: Author,
    tag_ref: str | UUID,
    target_ref: str | UUID,
) -> UUID:
    """Assign a tag to a base-network node or edge; return the meta edge UUID.

    A representation created by this call is kept even if the assignment is
    then rejected for a kind mismatch (a WARNING says so).

    Raises:
        UnknownItemError: unknown tag or target.
        ArchiveRuleError: not a tag, meta target, or tag/target kind mismatch.
        AuthorshipError: ``author`` did not create the tag.
    """
    tag = index.get(tag_ref)
    if not tag.is_tag:
        raise ArchiveRuleError(f"{tag.id} is not a tag node")
    if author.public_key_hex != tag.author:
        raise AuthorshipError("Only the tag's author may use this operation")

    target = index.items.get(index.resolve(target_ref))
    if target is None:
        raise UnknownItemError("UUID is not part of any network (neither base nor meta)")
    if target.is_meta:
        raise ArchiveRuleError("UUID should not be an item from the meta network")

    representation = index.representation_of(target.id)
    created = representation is None
    if representation is None:
        representation = _create_representation(index, author, target)
        index = ArchiveIndex(index.store.reopen())

    if tag.kind is ItemKind.NODE_TAG:
        expected, event_type = ItemKind.NODE_REPRESENTATION, MetaEventType.SET_NODE_TAG
        mismatch = "A node tag should point to a node representation"
    else:
        expected, event_type = ItemKind.EDGE_REPRESENTATION, MetaEventType.SET_EDGE_TAG
        mismatch = "An edge tag should point to an edge representation"
    if index.items[representation].kind is not expected:
        if created:
            logger.warning(
                "set_tag rejected: representation %s of %s was created but no "
                "tag was set; the representation remains in the meta log "
                "(intended, harmless).",
                representation,
                target.id,
            )
        raise ArchiveRuleError(mismatch)

    body = MetaEdge(event_type=event_type, source_node=tag.id, target_node=representation)
    append_meta(index, author, body)
    return body.edge_id
