from typing import Any
import mimetypes
import os
from ik.blob import ArchiveIndex
from ik.models import MediaType
from ik.events import create_vertex, create_event, write_event


def extract_content_and_mime(string):
    if os.path.exists(string) and os.path.isfile(string):
        mime_type, _ = mimetypes.guess_file_type(string)
        match mime_type:
            case "text/plain":
                media_type = MediaType.TEXT_PLAIN
            case "text/markdown":
                media_type = MediaType.TEXT_MARKDOWN
            case MediaType.IMAGE_JPEG.value:
                media_type = MediaType.IMAGE_JPEG
            case MediaType.IMAGE_PNG.value:
                media_type = MediaType.IMAGE_PNG
            case MediaType.IMAGE_TIFF.value:
                media_type = MediaType.IMAGE_TIFF
            case _:
                raise NotImplementedError("Media Type not supported")
        if media_type in {MediaType.TEXT_MARKDOWN, MediaType.TEXT_PLAIN}:
            with open(string, "rt", encoding="utf-8") as fj:
                content = fj.read()
        else:
            with open(string, "rb") as fj:
                content = fj.read()
    else:
        media_type = MediaType.TEXT_PLAIN
        content = string
    return content, media_type


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
