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
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Self

from indiek.core.canonical import (
    HASH_ALGORITHMS,
    SIGNATURE_ALGORITHMS,
    algorithm_of,
    event_hash,
)
from indiek.core.errors import IntegrityError
from indiek.core.models import EVENT_FORMAT_VERSION, TRANSCRIPTION_EVENT
from indiek.core.seals import SealChain, verify_seals
from indiek.core.signing import verify_event
from indiek.core.storage import BlobStore, EventLog, SealLog, strip_blob_prefix

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ChainState:
    """Tip of a verified log: prefixed hash of its last event, its length,
    and the signature algorithm of its last event (``None`` if empty).

    ``hashes[i]`` is the hash of event ``i`` (0-based) under its own
    ``hash_alg``; meta anchors are checked against the base ``hashes``.
    ``blobs[i]`` is the bare hex blob digest event ``i`` references, if any.
    """

    head: str | None
    count: int
    sig_alg: str | None = None
    hashes: tuple[str, ...] = field(default=(), compare=False, repr=False)
    blobs: tuple[str | None, ...] = field(default=(), compare=False, repr=False)


def _check_algorithms(event: dict[str, Any]) -> tuple[str, str]:
    """The event's ``(hash_alg, sig_alg)``, both supported and used consistently."""
    header = event.get("header", {})
    hash_alg, sig_alg = header.get("hash_alg"), header.get("sig_alg")
    if hash_alg not in HASH_ALGORITHMS or sig_alg not in SIGNATURE_ALGORITHMS:
        raise IntegrityError(
            f"Unsupported algorithm (hash_alg={hash_alg!r}, sig_alg={sig_alg!r})"
        )
    # A null prev_hash is checked by the chain rule; any other value, like the
    # signature, must carry the header's algorithm as prefix (bare hex fails).
    checks = [("signature", event.get("signature"), sig_alg)]
    if header.get("prev_hash") is not None:
        checks.append(("prev_hash", header.get("prev_hash"), hash_alg))
    for name, value, expected in checks:
        found = algorithm_of(value) if isinstance(value, str) else ""
        if found != expected:
            raise IntegrityError(
                f"Algorithm mismatch: {name} uses {found or 'no'!r} prefix, "
                f"header says {expected!r}"
            )
    return hash_alg, sig_alg


def _check_transcription(body: dict[str, Any], hashes: list[str]) -> None:
    """A transcription must attest a prefix of the events before it."""
    count = body.get("verified_count")
    head = body.get("verified_head")
    if (
        not isinstance(count, int)
        or isinstance(count, bool)
        or not 1 <= count <= len(hashes)
        or head != hashes[count - 1]
        or algorithm_of(head) != body.get("verified_hash_alg")
    ):
        raise IntegrityError("Transcription does not match chain")


def _check_anchor(header: dict[str, Any], anchors: Sequence[str], floor: int) -> int:
    """Check a meta event's ``base_seq`` / ``base_head``; return ``base_seq``."""
    seq, head = header.get("base_seq"), header.get("base_head")
    if (
        not isinstance(seq, int)
        or isinstance(seq, bool)
        or not 0 <= seq <= len(anchors)
    ):
        raise IntegrityError("Meta anchor does not match base history")
    if head != (anchors[seq - 1] if seq else None):
        raise IntegrityError("Meta anchor does not match base history")
    if seq < floor:
        raise IntegrityError("Meta anchor goes back in base history")
    return seq


def verify_chain(
    log: EventLog, blobs: BlobStore, anchors: Sequence[str] | None = None
) -> ChainState:
    """Verify algorithms, chain links, signatures, referenced blobs and
    transcriptions of ``log``.

    With ``anchors`` (the verified base ``hashes``), ``log`` is a meta log and
    every event's ``base_seq`` / ``base_head`` must point into them, with
    ``base_seq`` never decreasing.

    Raises:
        IntegrityError: ``"Unsupported format version …"``,
            ``"Unsupported algorithm …"``, ``"Algorithm mismatch …"``,
            ``"Chain broken!"``, ``"Data tampered or bad author!"``,
            ``"File corrupted or missing!"`` or
            ``"Transcription does not match chain"``; for meta logs also
            ``"Meta anchor does not match base history"`` or
            ``"Meta anchor goes back in base history"``.
    """
    hashes: list[str] = []  # hashes[i]: event i under its own hash_alg
    event_blobs: list[str | None] = []
    previous: dict[str, Any] | None = None
    sig_alg: str | None = None
    floor = 0  # highest base_seq seen so far (meta logs only)
    for event in log:
        version = event.get("header", {}).get("version")
        if version != EVENT_FORMAT_VERSION:
            raise IntegrityError(f"Unsupported format version {version!r}")
        hash_alg, sig_alg = _check_algorithms(event)
        # Only a log's first event may (and must) have prev_hash null, so a
        # truncated prefix is detected.  prev_hash uses this event's hash_alg.
        expected = None if previous is None else event_hash(previous, hash_alg)
        if event["header"].get("prev_hash") != expected:
            raise IntegrityError("Chain broken!")
        if not verify_event(event):
            raise IntegrityError("Data tampered or bad author!")
        if anchors is not None:
            floor = _check_anchor(event["header"], anchors, floor)
        body = event.get("body", {})
        blob_hash = body.get("blob_hash")
        if blob_hash and not blobs.verify(blob_hash):
            raise IntegrityError("File corrupted or missing!")
        if body.get("event_type") == TRANSCRIPTION_EVENT:
            _check_transcription(body, hashes)
        hashes.append(event_hash(event, hash_alg))
        event_blobs.append(strip_blob_prefix(blob_hash) if blob_hash else None)
        previous = event
    return ChainState(
        head=hashes[-1] if hashes else None,
        count=len(hashes),
        sig_alg=sig_alg,
        hashes=tuple(hashes),
        blobs=tuple(event_blobs),
    )


class ArchiveStore:
    """The base log, meta log, seal log and blob store of one archive,
    verified on open (base, then meta against base, then seals)."""

    def __init__(
        self,
        root: Path,
        base_log: EventLog,
        meta_log: EventLog,
        blobs: BlobStore,
        seal_log: SealLog | None = None,
    ) -> None:
        self.root = root
        self.base_log = base_log
        self.meta_log = meta_log
        self.blobs = blobs
        self.seal_log = seal_log or SealLog(root / "seals")
        self.base = verify_chain(base_log, blobs)
        self.meta = verify_chain(meta_log, blobs, anchors=self.base.hashes)
        self.seals: SealChain = verify_seals(self.seal_log, self.base, self.meta)
        if self.unreferenced_blobs:
            logger.warning(
                "%d unreferenced blob(s) in %s (no event uses them; delete them "
                "before sealing): %s",
                len(self.unreferenced_blobs),
                blobs.path,
                ", ".join(self.unreferenced_blobs),
            )
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
        return type(self)(
            self.root, self.base_log, self.meta_log, self.blobs, self.seal_log
        )

    @property
    def referenced_blobs(self) -> frozenset[str]:
        """Bare hex digests of every blob some base or meta event references."""
        return frozenset(b for b in (*self.base.blobs, *self.meta.blobs) if b)

    @property
    def unreferenced_blobs(self) -> list[str]:
        """Sorted names of files in the blob store that no event references."""
        referenced = self.referenced_blobs
        return [name for name in self.blobs.iter_hashes() if name not in referenced]

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
