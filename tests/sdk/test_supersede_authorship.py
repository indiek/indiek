"""Only the original author may supersede a node or edge (CLIPYPI:SUPERSEDE-AUTHORSHIP).

Owner decision 2026-10-17: others who disagree create their own node + edge.
Enforced twice: on replay (``IntegrityError``, so a hand-crafted log is
rejected) and on write (``AuthorshipError``, before any blob is written).
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest
from _builders import Builder

from indiek import Archive, Author, AuthorshipError, IntegrityError
from indiek.core.models import MediaType, SupersedeEdge

AUTHOR = Author.from_seed_hex("e1" * 32)  # public test vector, not a secret
OTHER = Author.from_seed_hex("e2" * 32)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    return tmp_path / "archive"


@pytest.fixture
def graph(root: Path) -> tuple[UUID, UUID, UUID]:
    """e1, e2 nodes and e3 = e1 -> e2 edge, all by AUTHOR."""
    ik = Archive.open(root, author=AUTHOR)
    a, b = ik.create_node("a", title="A"), ik.create_node("b")
    return a, b, ik.create_edge("e1", "e2", "ab")


def _blob_count(root: Path) -> int:
    return sum(1 for p in (root / "blobs").rglob("*") if p.is_file())


# -- replay (IntegrityError) ------------------------------------------------------


def test_replay_rejects_a_node_supersede_by_another_key(root: Path) -> None:
    build = Builder(root, AUTHOR)
    node = build.node("v1")
    build.supersede_node(node, "v2", author=OTHER)
    with pytest.raises(
        IntegrityError, match=f"Supersede by a non-author of item {node}"
    ):
        Archive.open(root)


def test_replay_rejects_an_edge_supersede_by_another_key(root: Path) -> None:
    build = Builder(root, AUTHOR)
    a, b = build.node("a"), build.node("b")
    edge = build.edge(a, b, "ab")
    build.raw_base(
        SupersedeEdge(
            edge_id=edge,
            source_node=a,
            target_node=b,
            blob_hash=build.blobs.put("ba"),
            media_type=MediaType.TEXT_PLAIN,
        ),
        author=OTHER,
    )
    with pytest.raises(
        IntegrityError, match=f"Supersede by a non-author of item {edge}"
    ):
        Archive.open(root)


def test_replay_rejects_a_later_non_author_supersede(root: Path) -> None:
    """The creator, not the latest reviser, is the reference author."""
    build = Builder(root, AUTHOR)
    node = build.node("v1")
    build.supersede_node(node, "v2")
    build.supersede_node(node, "v3", author=OTHER)
    with pytest.raises(IntegrityError, match="Supersede by a non-author"):
        Archive.open(root)


# -- write (AuthorshipError) ------------------------------------------------------


def test_the_author_may_supersede_repeatedly(
    root: Path, graph: tuple[UUID, UUID, UUID]
) -> None:
    ik = Archive.open(root, author=AUTHOR)
    ik.supersede_node("e1", "a2")
    ik.supersede_node("e1", "a3", title="A3")
    ik.supersede_edge("e3", "ab2")
    reopened = Archive.open(root)
    assert reopened.index.get("e1").body["title"] == "A3"
    assert reopened.index.get("e1").author == AUTHOR.public_key_hex
    assert reopened.index.get("e3").author == AUTHOR.public_key_hex


@pytest.mark.parametrize(
    ("method", "ref", "label"),
    [("supersede_node", "e1", "Node"), ("supersede_edge", "e3", "Edge")],
)
def test_another_author_is_refused_before_anything_is_written(
    root: Path,
    graph: tuple[UUID, UUID, UUID],
    method: str,
    ref: str,
    label: str,
) -> None:
    other = Archive.open(root, author=OTHER)
    head, blobs = other.head, _blob_count(root)
    with pytest.raises(
        AuthorshipError, match=f"Only the author of {label} '{ref}' may supersede it"
    ):
        getattr(other, method)(ref, "a rival revision")
    assert Archive.open(root).head == head
    assert _blob_count(root) == blobs  # no unreferenced blob is left behind


def test_another_author_can_disagree_with_their_own_node_and_edge(
    root: Path, graph: tuple[UUID, UUID, UUID]
) -> None:
    """The owner-sanctioned alternative to a rival supersede."""
    other = Archive.open(root, author=OTHER)
    rebuttal = other.create_node("a is wrong")
    other.create_edge(rebuttal, "e1", "disputes")
    assert other.index.get("e1").author == AUTHOR.public_key_hex
    assert other.index.get(rebuttal).author == OTHER.public_key_hex
