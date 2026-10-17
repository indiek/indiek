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

Hash-chain verification and the verified view of an archive on disk."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Self

from indiek.core.canonical import canonical_hash
from indiek.core.errors import IntegrityError
from indiek.core.signing import verify_body
from indiek.core.storage import BlobStore, EventLog

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ChainState:
    """Tip of a verified log: canonical hex hash of its last event, and length."""

    head: str | None
    count: int


def verify_chain(log: EventLog, blobs: BlobStore) -> ChainState:
    """Verify chain links, signatures and referenced blobs of ``log``.

    Raises:
        IntegrityError: ``"Chain broken!"``, ``"Data tampered or bad author!"``
            or ``"File corrupted or missing!"``.
    """
    head: str | None = None
    count = 0
    for event in log:
        if count and event["header"]["prev_hash"] != head:
            raise IntegrityError("Chain broken!")
        if not verify_body(event["body"], event["signature"], event["header"]["author"]):
            raise IntegrityError("Data tampered or bad author!")
        blob_hash = event["body"].get("blob_hash")
        if blob_hash and not blobs.verify(blob_hash):
            raise IntegrityError("File corrupted or missing!")
        head = canonical_hash(event).hex()
        count += 1
    return ChainState(head=head, count=count)


class ArchiveStore:
    """The base log, meta log and blob store of one archive, verified on open."""

    def __init__(
        self, root: Path, base_log: EventLog, meta_log: EventLog, blobs: BlobStore
    ) -> None:
        self.root = root
        self.base_log = base_log
        self.meta_log = meta_log
        self.blobs = blobs
        self.base = verify_chain(base_log, blobs)
        self.meta = verify_chain(meta_log, blobs)
        logger.info("ARCHIVE INTEGRITY VERIFIED")
        logger.debug(
            "The archive has %d events and %d meta events",
            self.base.count,
            self.meta.count,
        )

    @classmethod
    def open(cls, root: str | Path) -> Self:
        """Open and fully verify the archive rooted at ``root``."""
        root_path = Path(root)
        return cls(
            root_path,
            EventLog(root_path / "events"),
            EventLog(root_path / "meta" / "events"),
            BlobStore(root_path),
        )

    def reopen(self) -> Self:
        """Re-read and re-verify the same archive (after writes)."""
        return type(self)(self.root, self.base_log, self.meta_log, self.blobs)

    @property
    def base_head(self) -> str | None:
        return self.base.head

    @property
    def base_count(self) -> int:
        return self.base.count

    @property
    def meta_head(self) -> str | None:
        return self.meta.head

    @property
    def meta_count(self) -> int:
        return self.meta.count
