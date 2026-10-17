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

Create managed, URI and local-file nodes, and supersede node content."""

from __future__ import annotations

import hashlib
import mimetypes
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from indiek.core.author import Author
from indiek.core.errors import ArchiveRuleError
from indiek.core.index import ArchiveIndex
from indiek.core.models import MediaType, Node, ResourceType, SupersedeNode
from indiek.core.storage import BLOB_HASH_PREFIX
from indiek.ops.events import append_base, require_base_item

_DETECTABLE_MEDIA_TYPES: dict[str, MediaType] = {
    "text/plain": MediaType.TEXT_PLAIN,
    "text/markdown": MediaType.TEXT_MARKDOWN,
    "image/jpeg": MediaType.IMAGE_JPEG,
    "image/png": MediaType.IMAGE_PNG,
    "image/tiff": MediaType.IMAGE_TIFF,
}
_TEXT_MEDIA_TYPES = {MediaType.TEXT_PLAIN, MediaType.TEXT_MARKDOWN}


def detect_media_type(path: Path) -> MediaType:
    """Infer one of IndieK's archival media types from a file name.

    Raises:
        ArchiveRuleError: ``"Unsupported archival media type for <path>"``.
    """
    mime_type, _ = mimetypes.guess_type(path.name)
    try:
        return _DETECTABLE_MEDIA_TYPES[mime_type or ""]
    except KeyError:
        raise ArchiveRuleError(f"Unsupported archival media type for {path}") from None


def extract_content_and_mime(value: str) -> tuple[str | bytes, MediaType]:
    """Read ``value`` as a supported file if it names one, else as plain text."""
    path = Path(value)
    if path.is_file():
        media_type = detect_media_type(path)
        if media_type in _TEXT_MEDIA_TYPES:
            return path.read_text(encoding="utf-8"), media_type
        return path.read_bytes(), media_type
    return value, MediaType.TEXT_PLAIN


def create_managed_node(
    index: ArchiveIndex,
    author: Author,
    content: str | bytes,
    media_type: MediaType,
    title: str | None = None,
) -> UUID:
    """Store ``content`` in the blob store and append a ``create_node`` event."""
    digest = index.store.blobs.put(content)
    body = Node(
        title=title,
        resource_type=ResourceType.MANAGED,
        media_type=media_type,
        blob_hash=BLOB_HASH_PREFIX + digest,
    )
    append_base(index, author, body)
    return body.node_id


def create_uri_node(
    index: ArchiveIndex,
    author: Author,
    uri: str,
    title: str | None = None,
    media_type: MediaType | None = None,
) -> UUID:
    """Append a node referencing, but never fetching, an external URI."""
    body = Node(title=title, resource_type=ResourceType.URI, media_type=media_type, uri=uri)
    append_base(index, author, body)
    return body.node_id


def create_local_file_node(
    index: ArchiveIndex,
    author: Author,
    path: str | Path,
    title: str | None = None,
) -> UUID:
    """Append a pointer to a local file plus a fingerprint; nothing is copied.

    Raises:
        ArchiveRuleError: the file is missing or of an unsupported type.
    """
    resolved = Path(path).expanduser().resolve()
    if not resolved.is_file():
        raise ArchiveRuleError(
            f"Local file does not exist or is not a regular file: {resolved}"
        )
    data = resolved.read_bytes()
    body = Node(
        title=title or resolved.stem,
        resource_type=ResourceType.LOCAL_FILE,
        media_type=detect_media_type(resolved),
        path=str(resolved),
        file_size=len(data),
        file_hash=BLOB_HASH_PREFIX + hashlib.sha256(data).hexdigest(),
        last_verified=datetime.now(UTC),
    )
    append_base(index, author, body)
    return body.node_id


def supersede_node(
    index: ArchiveIndex,
    author: Author,
    ref: str | UUID,
    content: str | bytes,
    title: str | None = None,
    media_type: MediaType = MediaType.TEXT_MARKDOWN,
) -> UUID:
    """Append managed replacement content for an existing node.

    The node keeps its UUID and alias; ``title=None`` keeps the current title.
    """
    item = require_base_item(index, ref, edge=False)
    digest = index.store.blobs.put(content)
    body = SupersedeNode(
        node_id=item.id,
        title=item.body.get("title") if title is None else title,
        resource_type=ResourceType.MANAGED,
        media_type=media_type,
        blob_hash=BLOB_HASH_PREFIX + digest,
    )
    append_base(index, author, body)
    return item.id
