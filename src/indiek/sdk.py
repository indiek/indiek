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

The public facade of the IndieK SDK: :class:`Archive`."""

from __future__ import annotations

import os
import sys
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from itertools import chain
from pathlib import Path
from typing import Any, Self
from uuid import UUID

from filelock import FileLock, Timeout

from indiek.core.archive import ArchiveStore, VerificationLevel
from indiek.core.cache import default_cache_dir
from indiek.core.author import Author
from indiek.core.errors import (
    ArchiveLockedError,
    ArchiveRuleError,
    AuthorshipError,
    IntegrityError,
)
from indiek.core.index import ArchiveIndex, ItemKind, Network
from indiek.core.models import MediaType, ResourceType
from indiek.core.seals import Seal
from indiek.ops import (
    edges,
    export,
    ingest,
    manifest,
    nodes,
    tags,
    transcription,
)
from indiek.ops import seal as sealing
from indiek.ops.ingest import IngestResult
from indiek.ops.tags import TagKind

LOCK_FILE_NAME = ".ik.lock"
"""Advisory write lock at the archive root; not part of the archive (readers ignore it)."""
DEFAULT_LOCK_TIMEOUT = 10.0
"""Seconds a writer waits for another process's write lock (owner decision 2026-10-25)."""


@dataclass(frozen=True, slots=True)
class FsckReport:
    """Result of :meth:`Archive.fsck` (a ``FULL`` verification passed)."""

    path: Path
    base_count: int
    base_head: str | None
    meta_count: int
    meta_head: str | None
    seal_count: int
    latest_seal: Seal | None
    transcriptions: dict[str, int]
    blob_files: int
    referenced_blobs: int
    unreferenced_blobs: list[Path]
    untagged_representations: int


class Archive:
    """An IndieK archive opened from a folder, optionally with a signing author.

    Every write appends signed events and then refreshes :attr:`index`, so
    aliases (``e1``, ``m1``…) of new items are usable immediately.  Without an
    ``author`` the archive is read-only.

    Writes are serialised across processes (SDK2:WRITE-LOCK): each one holds
    the advisory lock ``<archive>/.ik.lock``, re-reads the archive inside it
    (so it chains onto the true head even if another process — the Desktop
    App, ``ik`` — wrote since this object was opened), appends, and releases.
    A writer waits up to ``lock_timeout`` seconds, then raises
    :class:`ArchiveLockedError`.  Reads never take the lock.

    Verification (owner decisions 2026-10-17): ``verify="incremental"`` (the
    default) recomputes every hash chain but skips the signature checks and
    blob re-hashing that this machine's cache (stored outside the archive) or
    a ``trusted_seal`` you obtained separately vouches for; seals found in the
    archive are always checked, never trusted.  ``"full"`` checks everything;
    ``"none"`` only parses and makes the archive read-only.  ``verify()``,
    ``fsck()``, ``seal()``, ``ingest()``, ``export_graphml()`` and
    ``write_manifest()`` always verify fully first.

    Example::

        ik = Archive.open("~/archives/demo", author=Author.from_seed_hex(seed))
        theorem = ik.create_node("Gödel's incompleteness theorem")
        tag = ik.create_tag("theorem", "A proven statement", kind="node")
        ik.set_tag(tag, theorem)
    """

    def __init__(
        self,
        path: Path,
        author: Author | None,
        index: ArchiveIndex,
        level: VerificationLevel = VerificationLevel.INCREMENTAL,
        lock_timeout: float = DEFAULT_LOCK_TIMEOUT,
    ) -> None:
        if lock_timeout < 0:
            raise ValueError(f"lock_timeout must be >= 0 seconds, not {lock_timeout}")
        self._path = path
        self.author = author
        self._index = index
        self._level = level
        self._lock_timeout = lock_timeout

    @classmethod
    def open(
        cls,
        path: str | Path,
        author: Author | None = None,
        *,
        verify: VerificationLevel | str = VerificationLevel.INCREMENTAL,
        trusted_seal: str | None = None,
        cache_dir: str | Path | None = None,
        lock_timeout: float | None = None,
    ) -> Self:
        """Open and verify the archive at ``path`` (which may not exist yet).

        Args:
            verify: ``"incremental"`` (default), ``"full"`` or ``"none"``.
            trusted_seal: a seal hash obtained through a separate, trusted
                route; the signatures of the events it covers are not
                re-checked (their hash chain still is).
            cache_dir: the verification cache directory; default: the
                user's cache dir (``IK_CACHE_DIR``, else per-OS convention).
            lock_timeout: seconds a write waits for another process's write
                lock before raising :class:`ArchiveLockedError` (default 10).

        Raises:
            IntegrityError: the archive on disk is corrupted or inconsistent,
                or ``trusted_seal`` is not in its seal log.
            ValueError: unknown ``verify`` level, or negative ``lock_timeout``.
        """
        root = Path(path).expanduser()
        timeout = DEFAULT_LOCK_TIMEOUT if lock_timeout is None else lock_timeout
        if timeout < 0:
            raise ValueError(f"lock_timeout must be >= 0 seconds, not {timeout}")
        level = VerificationLevel(verify)
        directory = (
            Path(cache_dir)
            if cache_dir is not None
            else default_cache_dir(
                environ=os.environ, platform=sys.platform, home=Path.home()
            )
        )
        store = ArchiveStore.open(
            root, level=level, trusted_seal=trusted_seal, cache_dir=directory
        )
        return cls(root, author, ArchiveIndex(store), level, timeout)

    # -- state -------------------------------------------------------------

    @property
    def path(self) -> Path:
        return self._path

    @property
    def verification(self) -> VerificationLevel:
        """The level this archive was opened with (used by every refresh)."""
        return self._level

    @property
    def index(self) -> ArchiveIndex:
        """Projection of the current state (items, aliases, tags)."""
        return self._index

    @property
    def head(self) -> str | None:
        """Prefixed hash (``sha256:<hex>``) of the last base event, or ``None``."""
        return self._index.head

    @property
    def meta_head(self) -> str | None:
        """Prefixed hash (``sha256:<hex>``) of the last meta event, or ``None``."""
        return self._index.meta_head

    def refresh(self, level: VerificationLevel | str | None = None) -> None:
        """Re-read and re-verify the archive (picks up writes by other
        processes), at ``level`` or at the level it was opened with."""
        chosen = self._level if level is None else VerificationLevel(level)
        self._index = ArchiveIndex(self._index.store.reopen(chosen))

    def _verify_fully(self) -> None:
        """Re-verify everything (``FULL``, which refreshes the cache), then keep
        working at this archive's own level."""
        self.refresh(VerificationLevel.FULL)
        if self._level is not VerificationLevel.FULL:
            self.refresh()

    def events(self, network: Network = "base") -> Iterator[dict[str, Any]]:
        """Iterate the raw events of the ``"base"`` or ``"meta"`` log, in order."""
        store = self._index.store
        if network == "base":
            return iter(store.base_log)
        if network == "meta":
            return iter(store.meta_log)
        raise ValueError(f"network must be 'base' or 'meta', not {network!r}")

    def _writer(self) -> Author:
        if self._level is VerificationLevel.NONE:
            raise ArchiveRuleError(
                "Writes need verification: this archive was opened with "
                "verify='none' (read-only)"
            )
        if self.author is None:
            raise AuthorshipError("An author is required to write to an archive")
        return self.author

    @contextmanager
    def _writing(self, *, full: bool = False) -> Iterator[Author]:
        """Hold the archive's write lock around one write operation.

        Inside the lock the archive is re-read (``full``: re-verified ``FULL``)
        so the write sees, and chains onto, what other processes appended; it
        is refreshed again afterwards, even when the operation failed midway.

        Raises:
            ArchiveLockedError: the lock stayed busy for ``lock_timeout`` s.
        """
        author = self._writer()
        self._path.mkdir(parents=True, exist_ok=True)
        lock_path = self._path / LOCK_FILE_NAME
        lock = FileLock(lock_path, timeout=self._lock_timeout)
        try:
            lock.acquire()
        except Timeout as exc:
            raise ArchiveLockedError(
                f"Archive is being written by another process (lock {lock_path} "
                f"still held after {self._lock_timeout:g} s); retry later"
            ) from exc
        try:
            if full:
                self._verify_fully()
            else:
                self.refresh()
            yield author
        finally:
            try:
                self.refresh()
            finally:
                lock.release()

    # -- base network --------------------------------------------------------

    def create_node(
        self,
        content: str | bytes | None = None,
        *,
        media_type: MediaType | None = None,
        title: str | None = None,
        resource_type: ResourceType = ResourceType.MANAGED,
        uri: str | None = None,
        path: str | Path | None = None,
    ) -> UUID:
        """Create a node and return its UUID.

        * ``managed`` (default): ``content`` is stored in the blob store.  It
          is always taken literally (a ``str`` is never read as a file path);
          ``str`` defaults to ``text/plain``, ``bytes`` need ``media_type``.
        * ``uri``: records ``uri`` (never fetched); ``media_type`` is a hint.
        * ``local_file``: records ``path`` plus size and SHA-256 fingerprint.
        """
        self._writer()
        kind = ResourceType(resource_type)
        if kind is ResourceType.URI and not uri:
            raise ArchiveRuleError("uri is required for uri nodes")
        if kind is ResourceType.LOCAL_FILE and path is None:
            raise ArchiveRuleError("path is required for local_file nodes")
        if kind is ResourceType.MANAGED:
            if content is None:
                raise ArchiveRuleError("content is required for managed nodes")
            if media_type is None:
                if isinstance(content, bytes):
                    raise ArchiveRuleError("media_type is required for bytes content")
                media_type = MediaType.TEXT_PLAIN
        with self._writing() as author:
            if kind is ResourceType.URI:
                assert uri is not None
                return nodes.create_uri_node(
                    self._index, author, uri, title, media_type
                )
            if kind is ResourceType.LOCAL_FILE:
                assert path is not None
                return nodes.create_local_file_node(self._index, author, path, title)
            assert content is not None and media_type is not None
            return nodes.create_managed_node(
                self._index, author, content, media_type, title
            )

    def create_edge(
        self, source: str | UUID, target: str | UUID, content: str | None = None
    ) -> UUID:
        """Create a directed edge between two existing nodes, carrying
        ``text/plain`` content or, with ``content=None``, none (format 3.1)."""
        with self._writing() as author:
            return edges.create_edge(self._index, author, source, target, content)

    def supersede_node(
        self,
        node: str | UUID,
        content: str | bytes,
        *,
        title: str | None = None,
        media_type: MediaType = MediaType.TEXT_MARKDOWN,
    ) -> UUID:
        """Replace a node's content (append-only); ``title=None`` keeps it."""
        with self._writing() as author:
            return nodes.supersede_node(
                self._index, author, node, content, title, media_type
            )

    def supersede_edge(self, edge: str | UUID, content: str | None = None) -> UUID:
        """Replace an edge's content (append-only), or drop it with
        ``content=None``; endpoints never change."""
        with self._writing() as author:
            return edges.supersede_edge(self._index, author, edge, content)

    # -- meta network --------------------------------------------------------

    def create_tag(self, name: str, description: str, *, kind: TagKind) -> UUID:
        """Define a node or edge tag; only this archive's author may assign it."""
        with self._writing() as author:
            return tags.create_tag(self._index, author, name, description, kind)

    def set_tag(self, tag: str | UUID, target: str | UUID) -> UUID:
        """Assign ``tag`` to a base node or edge; return the meta-edge UUID."""
        with self._writing() as author:
            return tags.set_tag(self._index, author, tag, target)

    # -- attestation -------------------------------------------------------

    def transcribe(self, network: Network = "base", *, note: str | None = None) -> str:
        """Attest the verified ``network`` log ("I verified it up to its head,
        under its algorithms, now") by appending a ``transcription`` event to
        that same log.  Any author may transcribe.  Returns the new head.

        Raises:
            ArchiveRuleError: the log is empty (nothing to attest).
            ValueError: ``network`` is neither ``"base"`` nor ``"meta"``.
        """
        if network not in ("base", "meta"):
            raise ValueError(f"network must be 'base' or 'meta', not {network!r}")
        with self._writing() as author:
            return transcription.transcribe(self._index, author, network, note)

    # -- seals ---------------------------------------------------------------

    def seal(self) -> Seal:
        """Re-verify the archive, then append a signed seal of both logs and
        the blob store.  ``Seal.hash`` is the one string committing to it all.

        Any author may seal.

        Raises:
            ArchiveRuleError: the archive is empty, unchanged since the latest
                seal, or its blob store holds unreferenced files (see
                :meth:`unreferenced_blobs`; delete them first).
        """
        with self._writing(full=True) as author:
            return sealing.seal(self._index, author)

    def unreferenced_blobs(self) -> list[Path]:
        """Files in the blob store that no event references (crash leftovers or
        hand-added files).  They are reported as a WARNING on open, block
        :meth:`seal`, and are safe to delete."""
        store = self._index.store
        return [store.blobs.path_for(name) for name in store.unreferenced_blobs]

    def seals(self) -> list[Seal]:
        """Every verified seal, oldest first."""
        return list(self._index.store.seals.seals)

    def verify(self, *, expect: str | None = None) -> Seal | None:
        """Re-read and fully (``FULL``) re-verify the archive from disk.

        Returns the seal whose hash is ``expect`` or, without ``expect``, the
        latest seal (``None`` if there is none).

        Raises:
            IntegrityError: the archive is invalid, or ``"Expected seal not
                found in seal log"``.
        """
        self._verify_fully()
        chain_ = self._index.store.seals
        if expect is None:
            return chain_.latest
        for candidate in chain_.seals:
            if candidate.hash == expect:
                return candidate
        raise IntegrityError("Expected seal not found in seal log")

    def fsck(self) -> FsckReport:
        """Fully verify the archive and report on its state.

        Raises:
            IntegrityError: the archive is invalid.
        """
        self._verify_fully()
        index = self._index
        store = index.store
        representations = {
            str(item.id)
            for item in index.items.values()
            if item.kind in {ItemKind.NODE_REPRESENTATION, ItemKind.EDGE_REPRESENTATION}
        }
        tagged = {
            str(item.body["target_node"])
            for item in index.items.values()
            if item.kind in {ItemKind.NODE_TAG_ASSIGNMENT, ItemKind.EDGE_TAG_ASSIGNMENT}
        }
        return FsckReport(
            path=self._path,
            base_count=store.base.count,
            base_head=store.base.head,
            meta_count=store.meta.count,
            meta_head=store.meta.head,
            seal_count=store.seals.count,
            latest_seal=store.seals.latest,
            transcriptions={n: len(r) for n, r in index.transcriptions.items()},
            blob_files=len(store.blobs.iter_hashes()),
            referenced_blobs=len(store.referenced_blobs),
            unreferenced_blobs=self.unreferenced_blobs(),
            untagged_representations=len(representations - tagged),
        )

    # -- bulk, export, documentation ----------------------------------------

    def ingest(
        self,
        *,
        input_folder: str | Path | None = None,
        edges_file: str | Path | None = None,
    ) -> IngestResult:
        """Create a node per entry of ``input_folder``, then an edge per line
        (``source,target,content``) of ``edges_file`` (after a ``FULL``
        verification)."""
        self._writer()
        file_paths: Sequence[Path] = (
            ingest.list_folder(input_folder) if input_folder else []
        )
        edge_definitions: list[str] = []
        if edges_file:
            with open(edges_file, "rt", encoding="utf-8") as handle:
                edge_definitions = handle.readlines()
        with self._writing(full=True) as author:
            return ingest.ingest(
                self._index,
                author,
                file_paths=file_paths,
                edge_definitions=edge_definitions,
            )

    def export_graphml(
        self, output_path: str | Path, tags: Sequence[str | UUID] = ()
    ) -> Path:
        """Write the base network as GraphML, optionally filtered by tags (OR),
        after a ``FULL`` verification."""
        self._verify_fully()
        return export.export_graphml(self._index, output_path, tags)

    def write_manifest(self) -> Path:
        """Write ``MANIFEST.json`` at the archive root, listing the author (if
        any) and every algorithm used in the archive (after a ``FULL``
        verification)."""
        self._verify_fully()
        self._path.mkdir(parents=True, exist_ok=True)
        keys = [self.author.public_key_hex] if self.author else []
        algorithms = manifest.collect_algorithms(
            chain(self.events("base"), self.events("meta"))
        )
        return manifest.write_manifest(self._path, keys, algorithms)
