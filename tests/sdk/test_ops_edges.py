"""Unit tests for ``indiek.ops.edges``."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID, uuid7

import pytest
from _builders import Builder

from indiek.core.archive import ArchiveStore
from indiek.core.author import Author
from indiek.core.errors import UnknownItemError
from indiek.core.index import ArchiveIndex, ItemKind
from indiek.core.models import MediaType
from indiek.ops import edges

AUTHOR = Author.from_seed_hex("77" * 32)  # public test vector, not a secret


@pytest.fixture
def root(tmp_path: Path) -> Path:
    return tmp_path / "archive"


@pytest.fixture
def two_nodes(root: Path) -> tuple[UUID, UUID]:
    build = Builder(root, AUTHOR)
    return build.node("source", title="S"), build.node("target")


def _index(root: Path) -> ArchiveIndex:
    return ArchiveIndex(ArchiveStore.open(root))


def test_create_edge_by_alias(root: Path, two_nodes: tuple[UUID, UUID]) -> None:
    edge_id = edges.create_edge(_index(root), AUTHOR, "e1", "e2", "implies")
    item = _index(root).get("e3")
    assert (item.id, item.kind) == (edge_id, ItemKind.EDGE)
    body = item.body
    assert (body["source_node"], body["target_node"]) == tuple(map(str, two_nodes))
    assert (body["resource_type"], body["media_type"]) == ("managed", MediaType.TEXT_PLAIN.value)
    assert _index(root).store.blobs.get_text(body["blob_hash"]) == "implies"


def test_create_edge_by_uuid(root: Path, two_nodes: tuple[UUID, UUID]) -> None:
    source, target = two_nodes
    edges.create_edge(_index(root), AUTHOR, str(source), target, "cites")
    assert _index(root).get("e3").body["target_node"] == str(target)


def test_file_like_content_is_stored_verbatim(
    root: Path, two_nodes: tuple[UUID, UUID], tmp_path: Path
) -> None:
    existing = tmp_path / "exists.txt"
    existing.write_text("file body", encoding="utf-8")
    edges.create_edge(_index(root), AUTHOR, "e1", "e2", str(existing))
    blob = _index(root).get("e3").body["blob_hash"]
    assert _index(root).store.blobs.get_text(blob) == str(existing)


def test_self_loop_is_allowed(root: Path, two_nodes: tuple[UUID, UUID]) -> None:
    edges.create_edge(_index(root), AUTHOR, "e1", "e1", "self")
    body = _index(root).get("e3").body
    assert body["source_node"] == body["target_node"] == str(two_nodes[0])


@pytest.mark.parametrize(
    ("source", "target", "message"),
    [
        ("e1", "e99", "Unknown ID or alias 'e99'"),
        ("garbage", "e1", "Unknown ID or alias 'garbage'"),
        (None, "e1", "SOURCE NODE .* NOT FOUND IN ARCHIVE"),
        ("e1", None, "TARGET NODE .* NOT FOUND IN ARCHIVE"),
    ],
)
def test_unknown_endpoints_write_nothing(
    root: Path,
    two_nodes: tuple[UUID, UUID],
    source: str | None,
    target: str | None,
    message: str,
) -> None:
    blobs_before = _index(root).store.blobs.iter_hashes()
    with pytest.raises(UnknownItemError, match=message):
        edges.create_edge(
            _index(root), AUTHOR, source or str(uuid7()), target or str(uuid7()), "dangling"
        )
    index = _index(root)
    assert index.store.base_count == 2
    # validation runs before the blob is written: no unreferenced blob is left
    assert index.store.blobs.iter_hashes() == blobs_before


@pytest.mark.parametrize(("source", "target"), [("e3", "e1"), ("e1", "e3")])
def test_edges_cannot_be_endpoints(
    root: Path, two_nodes: tuple[UUID, UUID], source: str, target: str
) -> None:
    edges.create_edge(_index(root), AUTHOR, "e1", "e2", "first")
    with pytest.raises(UnknownItemError, match="NODE .* NOT FOUND IN ARCHIVE"):
        edges.create_edge(_index(root), AUTHOR, source, target, "edge to edge")


def test_tag_cannot_be_an_endpoint(root: Path, two_nodes: tuple[UUID, UUID]) -> None:
    Builder(root, AUTHOR).tag("t")  # m1 lives in the meta network, never an endpoint
    with pytest.raises(UnknownItemError, match="SOURCE NODE"):
        edges.create_edge(_index(root), AUTHOR, "m1", "e1", "x")


# --- supersede_edge --------------------------------------------------------------


def test_supersede_edge_keeps_endpoints_title_and_alias(
    root: Path, two_nodes: tuple[UUID, UUID]
) -> None:
    edge_id = edges.create_edge(_index(root), AUTHOR, "e1", "e2", "r")
    assert edges.supersede_edge(_index(root), AUTHOR, "e3", "r2") == edge_id
    index = _index(root)
    item = index.get("e3")
    assert item.id == edge_id
    body = item.body
    assert body["event_type"] == "supersede_edge"
    assert (body["source_node"], body["target_node"]) == tuple(map(str, two_nodes))
    assert body["title"] is None
    assert body["media_type"] == MediaType.TEXT_PLAIN.value
    assert index.store.blobs.get_text(body["blob_hash"]) == "r2"


def test_supersede_edge_rejects_nodes(root: Path, two_nodes: tuple[UUID, UUID]) -> None:
    with pytest.raises(UnknownItemError, match="does not reference a base-network edge"):
        edges.supersede_edge(_index(root), AUTHOR, "e1", "x")


def test_supersede_edge_rejects_unknown_ids(root: Path) -> None:
    with pytest.raises(UnknownItemError, match="Edge 'e1' does not exist in this archive"):
        edges.supersede_edge(_index(root), AUTHOR, "e1", "x")
