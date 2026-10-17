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

On-disk storage primitives: the NDJSON event logs and the blob store.

Layout (relative to the archive root)::

    events/YYYY/MM/DD/events.ndjson        base event log
    meta/events/YYYY/MM/DD/events.ndjson   meta event log
    blobs/sha256/<hex[0:2]>/<hex[2:4]>/<sha256_hex>

A log is read by sorting every ``*ndjson`` path under its directory
lexicographically, then reading each file top to bottom.  Lines are parsed
with :func:`indiek.core.canonical.parse_line` (strict)."""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from indiek.core.canonical import parse_line
from indiek.core.models import EventModel, MetaEventModel

logger = logging.getLogger(__name__)

BLOB_HASH_PREFIX = "sha256:"


def strip_blob_prefix(blob_hash: str) -> str:
    """Return the bare hex digest of ``sha256:<hex>`` or ``<hex>``."""
    return blob_hash.removeprefix(BLOB_HASH_PREFIX)


class EventLog:
    """An append-only, date-sharded NDJSON event log rooted at ``path``."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def files(self) -> list[Path]:
        """Every log file, in canonical (lexicographic) read order."""
        return [Path(p) for p in sorted(str(p) for p in self.path.rglob("*ndjson"))]

    def __iter__(self) -> Iterator[dict[str, Any]]:
        for file_path in self.files():
            with open(file_path, "rt", encoding="utf-8") as handle:
                for line in handle:
                    yield parse_line(line)

    def append(self, event: EventModel | MetaEventModel) -> Path:
        """Append a signed event to the file of its header's UTC date."""
        ts = event.header.timestamp
        dir_path = self.path / ts.strftime("%Y/%m/%d")
        dir_path.mkdir(parents=True, exist_ok=True)
        file_path = dir_path / "events.ndjson"
        line = event.model_dump_json()
        with open(file_path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        logger.debug("EVENT %s written to %s", line, file_path)
        return file_path


class BlobStore:
    """Immutable, content-addressed (SHA-256) blob store of an archive."""

    def __init__(self, archive_root: str | Path) -> None:
        self.root_path = Path(archive_root)
        self.path = self.root_path / "blobs" / "sha256"

    def path_for(self, blob_hash: str) -> Path:
        """Sharded on-disk path of a (prefixed or bare) blob hash."""
        digest = strip_blob_prefix(blob_hash)
        return self.path / digest[:2] / digest[2:4] / digest

    def put(self, data: str | bytes) -> str:
        """Store ``data`` (``str`` is UTF-8 encoded) and return its bare hex hash."""
        raw = data.encode("utf-8") if isinstance(data, str) else data
        digest = hashlib.sha256(raw).hexdigest()
        file_path = self.path_for(digest)
        if file_path.exists():
            logger.debug("Blob %s already present; nothing written", digest)
            return digest
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_bytes(raw)
        logger.debug("Blob written to %s", file_path)
        return digest

    def get(self, blob_hash: str) -> bytes:
        """Raw bytes of a blob; raises ``FileNotFoundError`` if absent."""
        return self.path_for(blob_hash).read_bytes()

    def get_text(self, blob_hash: str) -> str:
        """A text blob decoded as UTF-8."""
        return self.get(blob_hash).decode("utf-8")

    def verify(self, blob_hash: str) -> bool:
        """Whether the blob exists and its bytes hash to its name."""
        try:
            raw = self.get(blob_hash)
        except FileNotFoundError:
            return False
        return hashlib.sha256(raw).hexdigest() == strip_blob_prefix(blob_hash)

    def iter_hashes(self) -> list[str]:
        """Sorted bare hex names of every blob file on disk."""
        if not self.path.is_dir():
            return []
        return sorted(p.name for p in self.path.glob("*/*/*") if p.is_file())
