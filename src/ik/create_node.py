from typing import Any
from ik.blob import ArchiveIndex
from ik.models import MediaType
from ik.events import create_vertex, create_event, write_event


def create_node_from_content(
    index: ArchiveIndex,
    content: Any,
    media_type: MediaType,
    pubkey,
    signing_key,
    title: str | None,
):
    blob_hash = index.arc.blob_store.create_and_persist_blob(content, media_type)

    body = create_vertex(
        title=title,
        blob_hash=blob_hash,
        data_type=media_type,
        blob_hash_prefix=index.arc.blob_store.blob_hash_prefix,
    )

    event = create_event(body=body, public_key=pubkey, archive=index)

    write_event(event, signing_key, index)


def run(
    *,
    node_content: str,
    node_title: str | None,
    curr_public_key,
    curr_signing_key,
    archive_idx,
    media_type,
):
    create_node_from_content(
        archive_idx,
        node_content,
        media_type,
        curr_public_key,
        curr_signing_key,
        node_title,
    )
