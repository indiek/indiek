"""Append supersede events for existing IndieK nodes."""

from typing import Any
from uuid import UUID

from ik.blob import ArchiveIndex
from ik.events import create_event, write_event
from ik.models import MediaType, ResourceType, SupersedeNode


def resolve_node_id(archive_idx: ArchiveIndex, node_id: str) -> UUID:
    """Resolve an archive UUID or human-friendly ID and verify it is a node."""
    resolved = archive_idx.human_to_machine_id_.get(node_id, node_id)
    try:
        item_uuid = UUID(str(resolved))
        item_info = archive_idx.id_info_[item_uuid]
    except (ValueError, KeyError) as exc:
        raise ValueError(f"Node {node_id!r} does not exist in this archive") from exc
    if item_info["is_meta"] or item_info["is_edge"]:
        raise ValueError(f"ID {node_id!r} does not reference a base-network node")
    return item_uuid


def create_supersede_event(
    *,
    archive_idx: ArchiveIndex,
    node_id: str,
    content: str | bytes,
    title: str | None,
    media_type: MediaType,
    public_key: str,
    signing_key: Any,
) -> str:
    """Store replacement managed content and append a ``supersede_node`` event."""
    item_uuid = resolve_node_id(archive_idx, node_id)
    previous_body = archive_idx.id_info_[item_uuid]["body"]
    blob_hash = archive_idx.arc.blob_store.create_and_persist_blob(content, media_type)
    body = SupersedeNode(
        node_id=item_uuid,
        title=previous_body.get("title") if title is None else title,
        resource_type=ResourceType.MANAGED,
        media_type=media_type,
        blob_hash=blob_hash,
    )
    event = create_event(body, public_key, archive_idx.arc)
    write_event(event, signing_key, archive_idx)
    return str(item_uuid)


def run(
    *,
    node_id: str,
    content: str,
    title: str | None,
    curr_public_key: str,
    curr_signing_key: Any,
    archive_idx: ArchiveIndex,
    media_type: MediaType = MediaType.TEXT_MARKDOWN,
) -> str:
    """CLI-facing helper for superseding a node's managed content."""
    return create_supersede_event(
        archive_idx=archive_idx,
        node_id=node_id,
        content=content,
        title=title,
        media_type=media_type,
        public_key=curr_public_key,
        signing_key=curr_signing_key,
    )
