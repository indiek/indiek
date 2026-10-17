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

Bulk ingestion: one managed node per folder entry, one edge per definition line."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from uuid import UUID

from indiek.core.author import Author
from indiek.core.index import ArchiveIndex
from indiek.ops.edges import create_edge
from indiek.ops.nodes import create_managed_node, extract_content_and_mime


@dataclass(frozen=True, slots=True)
class IngestResult:
    """UUIDs created by :func:`ingest`, in creation order."""

    node_ids: list[UUID] = field(default_factory=list)
    edge_ids: list[UUID] = field(default_factory=list)


def list_folder(folder: str | Path) -> list[Path]:
    """Every entry of ``folder`` (not recursive), sorted by path."""
    return sorted(Path(folder).iterdir(), key=str)


def _split_edge_definition(line: str) -> tuple[str, str, str]:
    """Split ``source,target,content`` on the first two commas."""
    # TODO(CLIPYPI:INGEST-ROBUSTNESS): strip the newline, reject short lines
    pivot = line.find(",", line.find(",") + 1)
    source, target = line[:pivot].split(",")
    return source, target, line[pivot + 1 :]


def ingest(
    index: ArchiveIndex,
    author: Author,
    *,
    file_paths: Sequence[str | Path] = (),
    edge_definitions: Sequence[str] = (),
) -> IngestResult:
    """Create a node per file path, then an edge per ``source,target,content`` line.

    Each path goes through :func:`~indiek.ops.nodes.extract_content_and_mime`
    and is titled by its stem.  Edge endpoints may use aliases of the nodes
    just created.  Stops at the first error; earlier writes are kept.
    """
    result = IngestResult()
    for file_path in file_paths:
        content, media_type = extract_content_and_mime(str(file_path))
        node_id = create_managed_node(
            index, author, content, media_type, Path(file_path).stem
        )
        result.node_ids.append(node_id)
        index = ArchiveIndex(index.store.reopen())
    for line in edge_definitions:
        source, target, content = _split_edge_definition(line)
        result.edge_ids.append(create_edge(index, author, source, target, content))
        index = ArchiveIndex(index.store.reopen())
    return result
