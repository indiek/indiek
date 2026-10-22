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
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Self

from indiek.core.cache import (
    VerificationCache,
    VerifiedTip,
    load_cache,
    save_cache,
)
from indiek.core.canonical import (
    DEFAULT_HASH_ALG,
    HASH_ALGORITHMS,
    SIGNATURE_ALGORITHMS,
    algorithm_of,
    canonical_bytes,
    digest,
    event_hash,
)
from indiek.core.errors import IntegrityError
from indiek.core.models import (
    CONTENTLESS_BODY_TYPES,
    CONTENTLESS_FORMAT_VERSION,
    SUPPORTED_FORMAT_VERSIONS,
    TRANSCRIPTION_EVENT,
)
from indiek.core.seals import SealChain, verify_seals
from indiek.core.signing import verify_event
from indiek.core.spec import differing_spec_files
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


def _verified_tip(state: ChainState) -> VerifiedTip | None:
    return VerifiedTip(state.count, state.head) if state.head else None


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


class VerificationLevel(StrEnum):
    """How much work opening an archive does (owner decision D13).

    * ``NONE``: parse only (debugging, recovery); the archive is read-only.
    * ``INCREMENTAL`` (SDK and CLI default): recompute the whole hash chain,
      anchors, transcriptions and seals, but skip Ed25519 checks and blob
      re-hashing where the local cache or a reader-supplied trusted seal
      vouches for them.  Never trusts a seal merely found in the archive.
    * ``FULL``: check everything, ignore the cache, then refresh it.
    """

    NONE = "none"
    INCREMENTAL = "incremental"
    FULL = "full"


class BlobChecker:
    """Checks each referenced blob once per open: a file whose ``(size,
    mtime_ns)`` matches ``known`` (the local cache) is not re-hashed."""

    def __init__(
        self, blobs: BlobStore, known: Mapping[str, tuple[int, int]] | None = None
    ) -> None:
        self.blobs = blobs
        self.known = dict(known or {})
        self.seen: dict[str, tuple[int, int]] = {}

    def check(self, blob_hash: str) -> bool:
        digest = strip_blob_prefix(blob_hash)
        if digest in self.seen:
            return True
        stat = self.blobs.stat(digest)
        if stat is None:
            return False
        if self.known.get(digest) != stat and not self.blobs.verify(digest):
            return False
        self.seen[digest] = stat
        return True


class _TrustNotConfirmed(Exception):
    """A trusted tip did not match the recomputed chain."""


def verify_chain(
    log: EventLog,
    blobs: BlobStore,
    anchors: Sequence[str] | None = None,
    *,
    trusted: Iterable[VerifiedTip | None] = (),
    checker: BlobChecker | None = None,
) -> ChainState:
    """Verify algorithms, chain links, signatures, referenced blobs and
    transcriptions of ``log``.

    With ``anchors`` (the verified base ``hashes``), ``log`` is a meta log and
    every event's ``base_seq`` / ``base_head`` must point into them, with
    ``base_seq`` never decreasing.

    ``trusted`` tips (from the local cache or a reader-supplied seal) let the
    signature checks of events ``1..tip.count`` be skipped, provided the
    recomputed chain confirms that event ``tip.count`` hashes to ``tip.head``.
    Any mismatch or error falls back to a full pass, so the error reported is
    always the one a full verification reports.

    Raises:
        IntegrityError: ``"Unsupported format version …"``,
            ``"Invalid resource type 'none' …"``,
            ``"Unsupported algorithm …"``, ``"Algorithm mismatch …"``,
            ``"Chain broken!"``, ``"Data tampered or bad author!"``,
            ``"File corrupted or missing!"`` or
            ``"Transcription does not match chain"``; for meta logs also
            ``"Meta anchor does not match base history"`` or
            ``"Meta anchor goes back in base history"``.
    """
    checker = checker or BlobChecker(blobs)
    tips = sorted(
        {tip for tip in trusted if tip is not None and tip.count > 0},
        key=lambda tip: tip.count,
        reverse=True,
    )
    for tip in tips:
        try:
            return _verify_chain(log, checker, anchors, tip)
        except _TrustNotConfirmed, IntegrityError:
            logger.debug("Trusted tip %s not confirmed; checking more", tip)
    return _verify_chain(log, checker, anchors, None)


_RESOURCE_FIELDS = (
    "media_type",
    "blob_hash",
    "uri",
    "path",
    "file_size",
    "file_hash",
    "last_verified",
)


def _check_version(event: dict[str, Any]) -> None:
    """Accept formats 3.0 and 3.1; ``resource_type: "none"`` (content-less
    edges) only on edge bodies of 3.1 events, with every resource field null."""
    version = event.get("header", {}).get("version")
    if version not in SUPPORTED_FORMAT_VERSIONS:
        raise IntegrityError(f"Unsupported format version {version!r}")
    body = event.get("body", {})
    if body.get("resource_type") != "none":
        return
    if version != CONTENTLESS_FORMAT_VERSION:
        raise IntegrityError(
            f"Invalid resource type 'none': needs format {CONTENTLESS_FORMAT_VERSION}"
        )
    if body.get("body_type") not in CONTENTLESS_BODY_TYPES:
        raise IntegrityError(
            "Invalid resource type 'none': only edges may have no content"
        )
    if any(body.get(field) is not None for field in _RESOURCE_FIELDS):
        raise IntegrityError(
            "Invalid resource type 'none': resource fields must be null"
        )


def _verify_chain(
    log: EventLog,
    checker: BlobChecker,
    anchors: Sequence[str] | None,
    tip: VerifiedTip | None,
) -> ChainState:
    hashes: list[str] = []  # hashes[i]: event i under its own hash_alg
    event_blobs: list[str | None] = []
    previous: dict[str, Any] | None = None
    sig_alg: str | None = None
    floor = 0  # highest base_seq seen so far (meta logs only)
    skip_until = tip.count if tip is not None else 0
    for position, event in enumerate(log, start=1):
        _check_version(event)
        hash_alg, sig_alg = _check_algorithms(event)
        # Only a log's first event may (and must) have prev_hash null, so a
        # truncated prefix is detected.  prev_hash uses this event's hash_alg.
        expected = None if previous is None else event_hash(previous, hash_alg)
        if event["header"].get("prev_hash") != expected:
            raise IntegrityError("Chain broken!")
        if position > skip_until and not verify_event(event):
            raise IntegrityError("Data tampered or bad author!")
        if anchors is not None:
            floor = _check_anchor(event["header"], anchors, floor)
        body = event.get("body", {})
        blob_hash = body.get("blob_hash")
        if blob_hash and not checker.check(blob_hash):
            raise IntegrityError("File corrupted or missing!")
        if body.get("event_type") == TRANSCRIPTION_EVENT:
            _check_transcription(body, hashes)
        hashes.append(event_hash(event, hash_alg))
        event_blobs.append(strip_blob_prefix(blob_hash) if blob_hash else None)
        if tip is not None and position == tip.count and hashes[-1] != tip.head:
            raise _TrustNotConfirmed
        previous = event
    if tip is not None and len(hashes) < tip.count:
        raise _TrustNotConfirmed
    return ChainState(
        head=hashes[-1] if hashes else None,
        count=len(hashes),
        sig_alg=sig_alg,
        hashes=tuple(hashes),
        blobs=tuple(event_blobs),
    )


def scan_chain(log: EventLog) -> ChainState:
    """Parse ``log`` and compute its hashes without checking anything (NONE)."""
    hashes: list[str] = []
    event_blobs: list[str | None] = []
    sig_alg: str | None = None
    for event in log:
        header = event.get("header", {})
        hash_alg = header.get("hash_alg")
        sig_alg = header.get("sig_alg")
        if hash_alg not in HASH_ALGORITHMS:
            hash_alg = DEFAULT_HASH_ALG
        hashes.append(event_hash(event, hash_alg))
        blob_hash = event.get("body", {}).get("blob_hash")
        event_blobs.append(strip_blob_prefix(blob_hash) if blob_hash else None)
    return ChainState(
        head=hashes[-1] if hashes else None,
        count=len(hashes),
        sig_alg=sig_alg if hashes else None,
        hashes=tuple(hashes),
        blobs=tuple(event_blobs),
    )


def _trusted_tips(
    seal_log: SealLog, trusted_seal: str
) -> tuple[VerifiedTip | None, VerifiedTip | None]:
    """Base and meta tips of the seal whose hash the reader supplied.

    Raises:
        IntegrityError: ``"Expected seal not found in seal log"``.
    """

    def tip(raw: Any) -> VerifiedTip | None:
        if not isinstance(raw, dict):
            return None
        count, head = raw.get("count"), raw.get("head")
        if type(count) is int and count > 0 and isinstance(head, str):
            return VerifiedTip(count, head)
        return None

    for raw in seal_log:
        try:
            seal_hash = digest(canonical_bytes(raw), raw.get("hash_alg"))
        except IntegrityError:
            continue
        if seal_hash == trusted_seal:
            return tip(raw.get("base")), tip(raw.get("meta"))
    raise IntegrityError("Expected seal not found in seal log")


class ArchiveStore:
    """The base log, meta log, seal log and blob store of one archive,
    verified on open (base, then meta against base, then seals) at ``level``.

    ``cache_dir`` enables the local verification cache (read at
    ``INCREMENTAL``, written at ``INCREMENTAL`` and ``FULL``); ``None``
    disables it.  ``trusted_seal`` is a seal hash the reader obtained through
    a separate route: signatures of the events it covers are not re-checked.
    """

    def __init__(
        self,
        root: Path,
        base_log: EventLog,
        meta_log: EventLog,
        blobs: BlobStore,
        seal_log: SealLog | None = None,
        *,
        level: VerificationLevel | str = VerificationLevel.FULL,
        trusted_seal: str | None = None,
        cache_dir: Path | None = None,
    ) -> None:
        self.root = root
        self.base_log = base_log
        self.meta_log = meta_log
        self.blobs = blobs
        self.seal_log = seal_log or SealLog(root / "seals")
        self.level = VerificationLevel(level)
        self.trusted_seal = trusted_seal
        self.cache_dir = cache_dir
        if self.level is VerificationLevel.NONE:
            self.base = scan_chain(base_log)
            self.meta = scan_chain(meta_log)
            try:
                self.seals = verify_seals(self.seal_log, self.base, self.meta)
            except IntegrityError:
                self.seals = SealChain()
            return

        use_cache = (
            cache_dir is not None and self.level is VerificationLevel.INCREMENTAL
        )
        cache = load_cache(cache_dir, root) if use_cache else VerificationCache()
        seal_base = seal_meta = None
        if trusted_seal is not None:
            seal_base, seal_meta = _trusted_tips(self.seal_log, trusted_seal)
        checker = BlobChecker(blobs, cache.blobs)
        self.base = verify_chain(
            base_log, blobs, trusted=(cache.base, seal_base), checker=checker
        )
        self.meta = verify_chain(
            meta_log,
            blobs,
            anchors=self.base.hashes,
            trusted=(cache.meta, seal_meta),
            checker=checker,
        )
        self.seals: SealChain = verify_seals(self.seal_log, self.base, self.meta)
        if cache_dir is not None:
            save_cache(
                cache_dir,
                root,
                VerificationCache(
                    base=_verified_tip(self.base),
                    meta=_verified_tip(self.meta),
                    blobs=checker.seen,
                ),
            )
        if self.level is VerificationLevel.FULL:
            for name in differing_spec_files(root):
                logger.warning(
                    "%s at the archive root differs from the copy shipped with this "
                    "indiek package (it was probably written by another indiek "
                    "version); it is informative only and does not affect validity",
                    name,
                )
        if self.unreferenced_blobs:
            logger.warning(
                "%d unreferenced blob(s) in %s (no event uses them; delete them "
                "before sealing): %s",
                len(self.unreferenced_blobs),
                blobs.path,
                ", ".join(self.unreferenced_blobs),
            )
        logger.info("ARCHIVE INTEGRITY VERIFIED (%s)", self.level.value)
        logger.debug(
            "The archive has %d events and %d meta events",
            self.base.count,
            self.meta.count,
        )

    @classmethod
    def open(
        cls,
        root: str | Path,
        *,
        level: VerificationLevel | str = VerificationLevel.FULL,
        trusted_seal: str | None = None,
        cache_dir: Path | None = None,
    ) -> Self:
        """Open and verify the archive rooted at ``root`` (``FULL`` by default)."""
        root_path = Path(root)
        return cls(
            root_path,
            EventLog(root_path / "events"),
            EventLog(root_path / "meta" / "events"),
            BlobStore(root_path),
            level=level,
            trusted_seal=trusted_seal,
            cache_dir=cache_dir,
        )

    def reopen(self, level: VerificationLevel | str | None = None) -> Self:
        """Re-read and re-verify the same archive (after writes), at ``level``
        or at the level it was opened with."""
        return type(self)(
            self.root,
            self.base_log,
            self.meta_log,
            self.blobs,
            self.seal_log,
            level=self.level if level is None else level,
            trusted_seal=self.trusted_seal,
            cache_dir=self.cache_dir,
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
