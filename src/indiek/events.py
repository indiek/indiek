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
"""

import logging
import os
from uuid import UUID

from indiek.blob import Archive, ArchiveIndex
from indiek.models import (
    EVENT_FORMAT_VERSION,
    Edge,
    EventHeader,
    EventModel,
    EventType,
    MetaEdge,
    MetaEventHeader,
    MetaEventModel,
    MetaEventType,
    MetaRepresentation,
    Node,
    ResourceType,
    SupersedeEdge,
    SupersedeNode,
    Tag,
)
from indiek.signing import sign_event

logger = logging.getLogger(__name__)


def create_representation(
    *,
    underlying_uuid_str: str,
    correct_event: MetaEventType,
    public_key: str,
    archive_index: ArchiveIndex,
    signing_key: str,
) -> UUID:
    """Create an event corresponding to representation and write it

    Args:
        underlying_uuid_str (str): The item ID (node or edge) of an item
            from the base network
        correct_event (MetaEventType): either MetaEventType.CREATE_NODE_REPRESENTATION or
            MetaEventType.CREATE_EDGE_REPRESENTATION

    Returns:
        UUID: The UUID of the newly created meta node
    """
    body: MetaRepresentation = create_meta_vertex(
        underlying_id=underlying_uuid_str, meta_event_type=correct_event
    )
    uuid_to_return = body.node_id
    meta_event = create_meta_event(body, public_key, archive_index)
    write_meta_event(meta_event, signing_key, archive_index)
    return uuid_to_return


def create_event(
    body: Node | Edge | SupersedeNode | SupersedeEdge,
    public_key: str,
    archive: Archive,
) -> EventModel:
    """Build an unsigned base-network event linked to the archive head."""
    prev_hash = archive.last_event_hash_ if archive.nevents_ else None

    return EventModel(
        header=EventHeader(
            version=EVENT_FORMAT_VERSION, prev_hash=prev_hash, author=public_key
        ),
        body=body,
    )


def create_meta_event(
    body: Tag | MetaRepresentation | MetaEdge,
    public_key: str,
    archive_idx: ArchiveIndex,
) -> MetaEventModel:
    """Build an unsigned tag-network event linked to the meta-log head."""
    prev_hash = (
        archive_idx.last_meta_event_hash_ if archive_idx.n_meta_events_ else None
    )

    return MetaEventModel(
        header=MetaEventHeader(
            version=EVENT_FORMAT_VERSION, prev_hash=prev_hash, author=public_key
        ),
        body=body,
    )


def create_vertex(
    *,
    title: str | None,
    resource_type: ResourceType = ResourceType.MANAGED,
    blob_hash: str | None = None,
    data_type=None,
    blob_hash_prefix: str = "sha256:",
    uri: str | None = None,
    path: str | None = None,
    file_size: int | None = None,
    file_hash: str | None = None,
    last_verified=None,
) -> Node:
    """Create a node body for managed, URI, or local-file resources."""
    kwargs = {
        "title": title,
        "resource_type": resource_type,
        "media_type": data_type,
        "uri": uri,
        "path": path,
        "file_size": file_size,
        "last_verified": last_verified,
    }
    if blob_hash is not None:
        kwargs["blob_hash"] = (
            blob_hash
            if blob_hash.startswith(blob_hash_prefix)
            else blob_hash_prefix + blob_hash
        )
    if file_hash is not None:
        kwargs["file_hash"] = (
            file_hash
            if file_hash.startswith(blob_hash_prefix)
            else blob_hash_prefix + file_hash
        )
    return Node(**kwargs)


def create_meta_vertex(
    *,
    underlying_id: UUID | None = None,
    tag: Tag | None = None,
    meta_event_type: MetaEventType | None = None,
) -> MetaRepresentation | Tag:
    """Creates a node in the dual network.

    Recall that a node in the dual network can correspond to a tag
    or to an edge from the original network, or to a node from the
    original network.

    When the meta node corresponds to a node or edge from the original
    network, it has an underlying_id attr set to the ID of the
    original network item.

    When the meta node corresponds to a tag, it has the name and description
    attr set.
    """
    if tag is None:
        if underlying_id is None or meta_event_type is None:
            raise ValueError(
                "A representation requires an underlying ID and event type"
            )
        return MetaRepresentation(
            event_type=meta_event_type, underlying_id=underlying_id
        )
    if underlying_id is not None:
        raise ValueError("A tag cannot also reference an underlying ID")
    return tag


def create_edge(
    source_id: UUID,
    target_id: UUID,
    blob_hash,
    data_type,
    blob_hash_prefix,
    archive: Archive,
) -> Edge:
    """Create an edge."""
    # verify that source and target exist
    source_present, target_present = False, False
    for event in archive.event_log:
        try:
            eid = UUID(event["body"]["node_id"])
            if eid == source_id:
                source_present = True
            if eid == target_id:
                target_present = True
        except KeyError:  # the event is not about a node
            continue
    if not source_present:
        raise ValueError(f"SOURCE NODE {source_id} NOT FOUND IN ARCHIVE")
    if not target_present:
        raise ValueError(f"TARGET NODE {target_id} NOT FOUND IN ARCHIVE")
    return Edge(
        event_type=EventType.CREATE_EDGE,
        media_type=data_type,
        blob_hash=blob_hash_prefix + blob_hash,
        source_node=source_id,
        target_node=target_id,
    )


def create_meta_edge(
    source_id: UUID,
    target_id: UUID,
    archive_idx: ArchiveIndex,
) -> MetaEdge:
    """Create an edge in the meta network.

    This always corresponds to one of the two following
    possibilities: Either it is setting a tag for a node in the
    original network, or it is setting a tag for an edge in
    the original network.

    Args:
        source_id (UUID): The source node ID in the meta network
        target_id (UUID): The target node ID in the meta network
        archive_idx (ArchiveIndex): The archive's index

    Returns:
        MetaEdge
    """
    # verify that source and target exist as meta nodes
    # verify also that the source is a tag
    # and that the target is a NodeRepresentation
    # if the tag is a node tag, and an EdgeRepresentation
    # if the tag is an edge tag
    meta_nodes = {
        k: v
        for k, v in archive_idx.id_info_.items()
        if v["is_meta"] and not v["is_edge"]
    }
    try:
        source_info = meta_nodes[source_id]
    except KeyError:
        raise ValueError(f"SOURCE NODE {source_id} NOT FOUND IN ARCHIVE'S META NETWORK")
    is_edge_tag = source_info["is_edge_tag"]
    is_node_tag = source_info["is_node_tag"]
    if not (is_edge_tag or is_node_tag):
        raise ValueError("Source meta node should be a tag")
    try:
        target_info = meta_nodes[target_id]
        if is_node_tag:
            if not target_info["is_node_representation"]:
                raise ValueError("A node tag should point to a node representation")
            event_type = MetaEventType.SET_NODE_TAG
        if is_edge_tag:
            if not target_info["is_edge_representation"]:
                raise ValueError("An edge tag should point to an edge representation")
            event_type = MetaEventType.SET_EDGE_TAG
    except KeyError:
        raise ValueError(f"TARGET NODE {target_id} NOT FOUND IN ARCHIVE'S META NETWORK")

    return MetaEdge(
        event_type=event_type,
        source_node=source_id,
        target_node=target_id,
    )


def sign_unsigned_event(event, signing_key):
    """Add an Ed25519 signature over an event body in-place."""
    event.signature = sign_event(event.body, signing_key)


def _write_event(
    event: EventModel | MetaEventModel, signing_key, log_root: str, label: str
) -> None:
    """Sign and append an event to its date-sharded NDJSON log."""
    sign_unsigned_event(event, signing_key)
    ts = event.header.timestamp
    dir_path = os.path.join(log_root, ts.strftime("%Y/%m/%d"))
    os.makedirs(dir_path, exist_ok=True)
    file_path = os.path.join(dir_path, "events.ndjson")
    event_json_str = event.model_dump_json()
    with open(file_path, "a", encoding="utf-8") as f:
        f.write(event_json_str + "\n")
    logger.debug("%s %s written to %s", label, event_json_str, file_path)
    logger.info("****** Rebuild Archive and Index for subsequent work *****")


def write_event(event: EventModel, signing_key, arc_idx: ArchiveIndex) -> None:
    """Sign and persist a base-network event."""
    _write_event(event, signing_key, str(arc_idx.arc.event_log.path_event_log), "EVENT")


def write_meta_event(event: MetaEventModel, signing_key, arc_idx: ArchiveIndex) -> None:
    """Sign and persist a meta-network event."""
    _write_event(
        event, signing_key, str(arc_idx.arc.meta_event_log.path_event_log), "META EVENT"
    )
