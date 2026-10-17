"""Unit tests for ``indiek.core.index`` (projection, aliases, ``resolve``)."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID, uuid7

import pytest
from _builders import Builder

from indiek.core.archive import ArchiveStore
from indiek.core.author import Author
from indiek.core.errors import IntegrityError, UnknownItemError
from indiek.core.index import ArchiveIndex, IndexedItem, ItemKind
from indiek.core.models import MediaType, MetaEdge, MetaEventType, SupersedeEdge, SupersedeNode

AUTHOR = Author.from_seed_hex("44" * 32)  # public test vector, not a secret
OTHER = Author.from_seed_hex("55" * 32)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    return tmp_path / "archive"


@pytest.fixture
def build(root: Path) -> Builder:
    return Builder(root, AUTHOR)


def _index(root: Path) -> ArchiveIndex:
    return ArchiveIndex(ArchiveStore.open(root))


# --- aliases and resolve -----------------------------------------------------


def test_empty_archive(root: Path) -> None:
    index = _index(root)
    assert index.items == {} and index.aliases == {}
    assert (index.head, index.meta_head) == (None, None)


def test_base_aliases_are_shared_by_nodes_and_edges(root: Path, build: Builder) -> None:
    a, b = build.node("a"), build.node("b")
    ab = build.edge(a, b, "ab")
    c = build.node("c")
    index = _index(root)
    assert index.aliases == {"e1": a, "e2": b, "e3": ab, "e4": c}
    assert index.alias_of(ab) == "e3"


def test_meta_aliases_count_tags_representations_and_assignments(
    root: Path, build: Builder
) -> None:
    node = build.node("n")
    tag = build.tag("t")
    rep = build.representation(node)
    assignment = build.assign(tag, rep)
    tag2 = build.tag("t2")
    index = _index(root)
    assert [index.aliases[f"m{i}"] for i in range(1, 5)] == [tag, rep, assignment, tag2]


def test_resolve_alias_uuid_string_and_uuid(root: Path, build: Builder) -> None:
    node = build.node("n")
    index = _index(root)
    assert index.resolve("e1") == node
    assert index.resolve(str(node)) == node
    assert index.resolve(node) == node


def test_resolve_does_not_check_existence_of_well_formed_uuids(root: Path) -> None:
    unknown = uuid7()
    assert _index(root).resolve(str(unknown)) == unknown


@pytest.mark.parametrize("ref", ["e99", "m1", "not-a-uuid", ""])
def test_resolve_rejects_unknown_aliases_and_garbage(root: Path, ref: str) -> None:
    with pytest.raises(UnknownItemError, match="Unknown ID or alias"):
        _index(root).resolve(ref)


def test_get_returns_item_or_raises(root: Path, build: Builder) -> None:
    node = build.node("n")
    index = _index(root)
    assert index.get("e1").id == node
    with pytest.raises(UnknownItemError):
        index.get(str(uuid7()))


# --- projection --------------------------------------------------------------


def test_items_are_typed(root: Path, build: Builder) -> None:
    a, b = build.node("a", title="A"), build.node("b")
    ab = build.edge(a, b, "ab")
    node_tag, edge_tag = build.tag("nt"), build.tag("et", kind="edge")
    rep = build.representation(ab, kind="edge")
    assignment = build.assign(edge_tag, rep, kind="edge")
    items = _index(root).items

    node = items[a]
    assert isinstance(node, IndexedItem)
    assert (node.alias, node.kind, node.author) == ("e1", ItemKind.NODE, AUTHOR.public_key_hex)
    assert node.body["title"] == "A"
    assert not node.is_meta and not node.is_edge
    assert items[ab].kind is ItemKind.EDGE and items[ab].is_edge
    assert items[node_tag].kind is ItemKind.NODE_TAG and items[node_tag].is_tag
    assert items[edge_tag].kind is ItemKind.EDGE_TAG
    assert items[rep].kind is ItemKind.EDGE_REPRESENTATION and items[rep].is_meta
    assert items[assignment].kind is ItemKind.EDGE_TAG_ASSIGNMENT
    assert items[ab].tags == {edge_tag}
    assert items[a].tags == set()


def test_supersede_replaces_projection_and_author_but_keeps_alias(
    root: Path, build: Builder
) -> None:
    node = build.node("v1", title="T")
    build.supersede_node(node, "v2", title="T2", author=OTHER)
    item = _index(root).items[node]
    assert item.alias == "e1"
    assert item.body["event_type"] == "supersede_node"
    assert item.body["title"] == "T2"
    assert item.author == OTHER.public_key_hex


def test_representation_maps_both_directions(root: Path, build: Builder) -> None:
    node = build.node("n")
    rep = build.representation(node)
    index = _index(root)
    assert index.representation_of(node) == rep
    assert index.underlying_of(rep) == node
    assert index.representation_of(uuid7()) is None


def test_two_tags_on_one_item(root: Path, build: Builder) -> None:
    node = build.node("n")
    t1, t2 = build.tag("t1"), build.tag("t2")
    rep = build.representation(node)
    build.assign(t1, rep)
    build.assign(t2, rep)
    build.assign(t2, rep)  # repeated assignment is idempotent in the projection
    assert _index(root).items[node].tags == {t1, t2}


# --- replay integrity errors -------------------------------------------------


def test_supersede_of_unknown_item(root: Path, build: Builder) -> None:
    digest = build.blobs.put("x")
    build.raw_base(
        SupersedeNode(node_id=uuid7(), blob_hash=digest, media_type=MediaType.TEXT_PLAIN)
    )
    with pytest.raises(IntegrityError, match="Supersede event references unknown item"):
        _index(root)


def test_supersede_type_mismatch(root: Path, build: Builder) -> None:
    a, b = build.node("a"), build.node("b")
    digest = build.blobs.put("x")
    build.raw_base(
        SupersedeEdge(
            edge_id=a, source_node=a, target_node=b, blob_hash=digest,
            media_type=MediaType.TEXT_PLAIN,
        )
    )
    with pytest.raises(IntegrityError, match="Supersede event type does not match item"):
        _index(root)


def test_supersede_edge_cannot_change_endpoints(root: Path, build: Builder) -> None:
    a, b, c = build.node("a"), build.node("b"), build.node("c")
    ab = build.edge(a, b, "ab")
    build.supersede_edge(ab, a, c, "ac")
    with pytest.raises(IntegrityError, match="Supersede edge events cannot change endpoints"):
        _index(root)


def test_assignment_to_unknown_representation(root: Path, build: Builder) -> None:
    tag = build.tag("t")
    build.raw_meta(
        MetaEdge(source_node=tag, target_node=uuid7(), event_type=MetaEventType.SET_NODE_TAG)
    )
    with pytest.raises(IntegrityError, match="Tag assignment references an unknown representation"):
        _index(root)


def test_resolve_returns_uuid_type(root: Path, build: Builder) -> None:
    build.node("n")
    assert isinstance(_index(root).resolve("e1"), UUID)
