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

Append supersede events for existing IndieK edges."""

from typing import Any
from uuid import UUID

from indiek.blob import ArchiveIndex
from indiek.events import create_event, write_event
from indiek.models import MediaType, ResourceType, SupersedeEdge


def resolve_edge_id(archive_idx: ArchiveIndex, edge_id: str) -> UUID:
    """Resolve an archive UUID or human-friendly ID and verify it is an edge."""
    resolved = archive_idx.human_to_machine_id_.get(edge_id, edge_id)
    try:
        item_uuid = UUID(str(resolved))
        item_info = archive_idx.id_info_[item_uuid]
    except (ValueError, KeyError) as exc:
        raise ValueError(f"Edge {edge_id!r} does not exist in this archive") from exc
    if item_info["is_meta"] or not item_info["is_edge"]:
        raise ValueError(f"ID {edge_id!r} does not reference a base-network edge")
    return item_uuid


def create_supersede_event(
    *,
    archive_idx: ArchiveIndex,
    edge_id: str,
    content: str | bytes,
    public_key: str,
    signing_key: Any,
    media_type: MediaType = MediaType.TEXT_PLAIN,
) -> str:
    """Store replacement content while preserving the edge's original endpoints."""
    item_uuid = resolve_edge_id(archive_idx, edge_id)
    previous_body = archive_idx.id_info_[item_uuid]["body"]
    blob_hash = archive_idx.arc.blob_store.create_and_persist_blob(content, media_type)
    body = SupersedeEdge(
        edge_id=item_uuid,
        source_node=UUID(str(previous_body["source_node"])),
        target_node=UUID(str(previous_body["target_node"])),
        title=previous_body.get("title"),
        resource_type=ResourceType.MANAGED,
        media_type=media_type,
        blob_hash=blob_hash,
    )
    event = create_event(body, public_key, archive_idx.arc)
    write_event(event, signing_key, archive_idx)
    return str(item_uuid)


def run(
    *,
    edge_id: str,
    content: str,
    curr_public_key: str,
    curr_signing_key: Any,
    archive_idx: ArchiveIndex,
) -> str:
    """CLI-facing helper for superseding an edge's managed content."""
    return create_supersede_event(
        archive_idx=archive_idx,
        edge_id=edge_id,
        content=content,
        public_key=curr_public_key,
        signing_key=curr_signing_key,
    )
