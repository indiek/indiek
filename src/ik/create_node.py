"""Create managed, URI, and local-file nodes in an IndieK archive."""

from datetime import datetime, timezone
import hashlib
import mimetypes
from pathlib import Path
from typing import Any

from ik.blob import ArchiveIndex
from ik.events import create_event, create_vertex, write_event
from ik.models import MediaType, ResourceType


def extract_content_and_mime(value: str) -> tuple[str | bytes, MediaType]:
    """Read a supported file or treat ``value`` as UTF-8 plain-text content."""
    path = Path(value)
    if path.is_file():
        media_type = detect_media_type(path)
        if media_type in {MediaType.TEXT_MARKDOWN, MediaType.TEXT_PLAIN}:
            return path.read_text(encoding="utf-8"), media_type
        return path.read_bytes(), media_type
    return value, MediaType.TEXT_PLAIN


def detect_media_type(path: Path) -> MediaType:
    """Infer one of IndieK's allowed media types from a file path."""
    mime_type, _ = mimetypes.guess_type(path.name)
    media_types = {
        "text/plain": MediaType.TEXT_PLAIN,
        "text/markdown": MediaType.TEXT_MARKDOWN,
        "image/jpeg": MediaType.IMAGE_JPEG,
        "image/png": MediaType.IMAGE_PNG,
        "image/tiff": MediaType.IMAGE_TIFF,
    }
    try:
        return media_types[mime_type or ""]
    except KeyError as exc:
        raise ValueError(f"Unsupported archival media type for {path}") from exc


def create_node_from_content(
    index: ArchiveIndex,
    content: Any,
    media_type: MediaType,
    pubkey: str,
    signing_key: Any,
    title: str | None,
) -> str:
    """Persist managed content and append a node creation event.

    Returns the new node ID as a string so callers can immediately address it.
    """
    blob_hash = index.arc.blob_store.create_and_persist_blob(content, media_type)
    body = create_vertex(
        title=title,
        resource_type=ResourceType.MANAGED,
        blob_hash=blob_hash,
        data_type=media_type,
        blob_hash_prefix=index.arc.blob_store.blob_hash_prefix,
    )
    event = create_event(body=body, public_key=pubkey, archive=index.arc)
    write_event(event, signing_key, index)
    return str(body.node_id)


def create_uri_node(
    index: ArchiveIndex,
    url: str,
    title: str | None,
    media_type_hint: MediaType | None,
    pubkey: str,
    signing_key: Any,
) -> str:
    """Append a node that references, but does not fetch, an external URI."""
    body = create_vertex(
        title=title,
        resource_type=ResourceType.URI,
        data_type=media_type_hint,
        uri=url,
    )
    event = create_event(body=body, public_key=pubkey, archive=index.arc)
    write_event(event, signing_key, index)
    return str(body.node_id)


def create_local_file_node(
    index: ArchiveIndex,
    file_path: str | Path,
    title: str | None,
    pubkey: str,
    signing_key: Any,
) -> str:
    """Append an external local-file reference with a verification fingerprint."""
    path = Path(file_path).expanduser().resolve()
    if not path.is_file():
        raise ValueError(f"Local file does not exist or is not a regular file: {path}")
    data = path.read_bytes()
    body = create_vertex(
        title=title or path.stem,
        resource_type=ResourceType.LOCAL_FILE,
        data_type=detect_media_type(path),
        path=str(path),
        file_size=len(data),
        file_hash=hashlib.sha256(data).hexdigest(),
        last_verified=datetime.now(timezone.utc),
    )
    event = create_event(body=body, public_key=pubkey, archive=index.arc)
    write_event(event, signing_key, index)
    return str(body.node_id)


def run(
    *,
    node_content: str | None,
    node_title: str | None,
    curr_public_key: str,
    curr_signing_key: Any,
    archive_idx: ArchiveIndex,
    media_type: MediaType | None = None,
    resource_type: ResourceType = ResourceType.MANAGED,
    uri: str | None = None,
    path: str | None = None,
) -> str:
    """CLI-facing dispatcher for all node resource types."""
    if resource_type is ResourceType.URI:
        if not uri:
            raise ValueError("--uri is required when --resource-type uri")
        return create_uri_node(archive_idx, uri, node_title, media_type, curr_public_key, curr_signing_key)
    if resource_type is ResourceType.LOCAL_FILE:
        if not path:
            raise ValueError("--path is required when --resource-type local_file")
        return create_local_file_node(archive_idx, path, node_title, curr_public_key, curr_signing_key)
    if node_content is None or media_type is None:
        raise ValueError("--content is required for managed nodes")
    return create_node_from_content(
        archive_idx, node_content, media_type, curr_public_key, curr_signing_key, node_title
    )
