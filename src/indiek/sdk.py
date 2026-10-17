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

from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any, Literal, Self
from uuid import UUID

from indiek.core.archive import ArchiveStore
from indiek.core.author import Author
from indiek.core.errors import ArchiveRuleError, AuthorshipError
from indiek.core.index import ArchiveIndex
from indiek.core.models import MediaType, ResourceType
from indiek.ops import edges, export, ingest, manifest, nodes, tags
from indiek.ops.ingest import IngestResult
from indiek.ops.tags import TagKind

Network = Literal["base", "meta"]


class Archive:
    """An IndieK archive opened from a folder, optionally with a signing author.

    Every write appends signed events and then refreshes :attr:`index`, so
    aliases (``e1``, ``m1``…) of new items are usable immediately.  Without an
    ``author`` the archive is read-only.

    Example::

        ik = Archive.open("~/archives/demo", author=Author.from_seed_hex(seed))
        theorem = ik.create_node("Gödel's incompleteness theorem")
        tag = ik.create_tag("theorem", "A proven statement", kind="node")
        ik.set_tag(tag, theorem)
    """

    def __init__(self, path: Path, author: Author | None, index: ArchiveIndex) -> None:
        self._path = path
        self.author = author
        self._index = index

    @classmethod
    def open(cls, path: str | Path, author: Author | None = None) -> Self:
        """Open and fully verify the archive at ``path`` (which may not exist yet).

        Raises:
            IntegrityError: the archive on disk is corrupted or inconsistent.
        """
        root = Path(path).expanduser()
        return cls(root, author, ArchiveIndex(ArchiveStore.open(root)))

    # -- state -------------------------------------------------------------

    @property
    def path(self) -> Path:
        return self._path

    @property
    def index(self) -> ArchiveIndex:
        """Projection of the current state (items, aliases, tags)."""
        return self._index

    @property
    def head(self) -> str | None:
        """Canonical hash of the last base event, or ``None`` if empty."""
        return self._index.head

    @property
    def meta_head(self) -> str | None:
        """Canonical hash of the last meta event, or ``None`` if empty."""
        return self._index.meta_head

    def refresh(self) -> None:
        """Re-read and re-verify the archive (picks up writes by other processes)."""
        self._index = ArchiveIndex(self._index.store.reopen())

    def events(self, network: Network = "base") -> Iterator[dict[str, Any]]:
        """Iterate the raw events of the ``"base"`` or ``"meta"`` log, in order."""
        store = self._index.store
        if network == "base":
            return iter(store.base_log)
        if network == "meta":
            return iter(store.meta_log)
        raise ValueError(f"network must be 'base' or 'meta', not {network!r}")

    def _writer(self) -> Author:
        if self.author is None:
            raise AuthorshipError("An author is required to write to an archive")
        return self.author

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
        author = self._writer()
        kind = ResourceType(resource_type)
        if kind is ResourceType.URI:
            if not uri:
                raise ArchiveRuleError("uri is required for uri nodes")
            node_id = nodes.create_uri_node(self._index, author, uri, title, media_type)
        elif kind is ResourceType.LOCAL_FILE:
            if path is None:
                raise ArchiveRuleError("path is required for local_file nodes")
            node_id = nodes.create_local_file_node(self._index, author, path, title)
        else:
            if content is None:
                raise ArchiveRuleError("content is required for managed nodes")
            if media_type is None:
                if isinstance(content, bytes):
                    raise ArchiveRuleError("media_type is required for bytes content")
                media_type = MediaType.TEXT_PLAIN
            node_id = nodes.create_managed_node(
                self._index, author, content, media_type, title
            )
        self.refresh()
        return node_id

    def create_edge(self, source: str | UUID, target: str | UUID, content: str) -> UUID:
        """Create a directed ``text/plain`` edge between two existing nodes."""
        edge_id = edges.create_edge(self._index, self._writer(), source, target, content)
        self.refresh()
        return edge_id

    def supersede_node(
        self,
        node: str | UUID,
        content: str | bytes,
        *,
        title: str | None = None,
        media_type: MediaType = MediaType.TEXT_MARKDOWN,
    ) -> UUID:
        """Replace a node's content (append-only); ``title=None`` keeps it."""
        node_id = nodes.supersede_node(
            self._index, self._writer(), node, content, title, media_type
        )
        self.refresh()
        return node_id

    def supersede_edge(self, edge: str | UUID, content: str) -> UUID:
        """Replace an edge's content (append-only); endpoints never change."""
        edge_id = edges.supersede_edge(self._index, self._writer(), edge, content)
        self.refresh()
        return edge_id

    # -- meta network --------------------------------------------------------

    def create_tag(self, name: str, description: str, *, kind: TagKind) -> UUID:
        """Define a node or edge tag; only this archive's author may assign it."""
        tag_id = tags.create_tag(self._index, self._writer(), name, description, kind)
        self.refresh()
        return tag_id

    def set_tag(self, tag: str | UUID, target: str | UUID) -> UUID:
        """Assign ``tag`` to a base node or edge; return the meta-edge UUID."""
        try:
            return tags.set_tag(self._index, self._writer(), tag, target)
        finally:
            self.refresh()

    # -- bulk, export, documentation ----------------------------------------

    def ingest(
        self,
        *,
        input_folder: str | Path | None = None,
        edges_file: str | Path | None = None,
    ) -> IngestResult:
        """Create a node per entry of ``input_folder``, then an edge per line
        (``source,target,content``) of ``edges_file``."""
        file_paths: Sequence[Path] = ingest.list_folder(input_folder) if input_folder else []
        edge_definitions: list[str] = []
        if edges_file:
            with open(edges_file, "rt", encoding="utf-8") as handle:
                edge_definitions = handle.readlines()
        try:
            return ingest.ingest(
                self._index,
                self._writer(),
                file_paths=file_paths,
                edge_definitions=edge_definitions,
            )
        finally:
            self.refresh()

    def export_graphml(self, output_path: str | Path, tags: Sequence[str | UUID] = ()) -> Path:
        """Write the base network as GraphML, optionally filtered by tags (OR)."""
        return export.export_graphml(self._index, output_path, tags)

    def write_manifest(self) -> Path:
        """Write ``MANIFEST.json`` at the archive root (listing the author, if any)."""
        self._path.mkdir(parents=True, exist_ok=True)
        keys = [self.author.public_key_hex] if self.author else []
        return manifest.write_manifest(self._path, keys)
