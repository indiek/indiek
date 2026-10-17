"""Unit tests for ``indiek.ops.tags``."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid7

import pytest
from _builders import Builder

from indiek.core.archive import ArchiveStore
from indiek.core.author import Author
from indiek.core.errors import ArchiveRuleError, AuthorshipError, UnknownItemError
from indiek.core.index import ArchiveIndex, ItemKind
from indiek.ops import tags

AUTHOR = Author.from_seed_hex("88" * 32)  # public test vector, not a secret
OTHER = Author.from_seed_hex("99" * 32)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    return tmp_path / "archive"


@pytest.fixture
def graph(root: Path) -> tuple[UUID, UUID, UUID]:
    """e1, e2 nodes and e3 = e1 -> e2 edge."""
    build = Builder(root, AUTHOR)
    a, b = build.node("a"), build.node("b")
    return a, b, build.edge(a, b, "ab")


def _index(root: Path) -> ArchiveIndex:
    return ArchiveIndex(ArchiveStore.open(root))


def _meta_types(root: Path) -> list[str]:
    return [event["body"]["event_type"] for event in _index(root).store.meta_log]


# --- create_tag ----------------------------------------------------------------


@pytest.mark.parametrize("kind", ["node", "edge"])
def test_create_tag(root: Path, kind: Literal["node", "edge"]) -> None:
    tag_id = tags.create_tag(
        _index(root), AUTHOR, "theorem", "A proven statement", kind
    )
    index = _index(root)
    item = index.get("m1")
    assert item.id == tag_id
    assert item.kind is ItemKind(f"{kind}_tag")
    assert (item.body["name"], item.body["description"]) == (
        "theorem",
        "A proven statement",
    )
    assert item.body["body_type"] == "tag"
    assert item.author == AUTHOR.public_key_hex
    assert index.store.base_count == 0
    assert index.store.blobs.iter_hashes() == []


def test_duplicate_tag_names_are_distinct(root: Path) -> None:
    first = tags.create_tag(_index(root), AUTHOR, "same", "one", "node")
    second = tags.create_tag(_index(root), AUTHOR, "same", "two", "node")
    assert first != second


def test_create_tag_rejects_unknown_kind(root: Path) -> None:
    with pytest.raises(ArchiveRuleError, match="kind"):
        tags.create_tag(_index(root), AUTHOR, "t", "d", "graph")  # type: ignore[arg-type]


# --- set_tag happy paths ---------------------------------------------------------


def test_tag_a_node(root: Path, graph: tuple[UUID, UUID, UUID]) -> None:
    tag_id = tags.create_tag(_index(root), AUTHOR, "t", "d", "node")
    assignment = tags.set_tag(_index(root), AUTHOR, "m1", "e1")
    index = _index(root)
    assert _meta_types(root) == [
        "create_node_tag",
        "create_node_representation",
        "set_node_tag",
    ]
    representation = index.representation_of(graph[0])
    assert representation == index.aliases["m2"]
    item = index.get(assignment)
    assert item.body["body_type"] == "edge"
    assert index.get("m2").body["underlying_id"] == str(graph[0])
    assert item.kind is ItemKind.NODE_TAG_ASSIGNMENT
    assert item.body["source_node"] == str(tag_id)
    assert item.body["target_node"] == str(representation)
    assert index.items[graph[0]].tags == {tag_id}


def test_tag_an_edge_by_uuid(root: Path, graph: tuple[UUID, UUID, UUID]) -> None:
    tag_id = tags.create_tag(_index(root), AUTHOR, "t", "d", "edge")
    tags.set_tag(_index(root), AUTHOR, str(tag_id), str(graph[2]))
    assert _meta_types(root)[1:] == ["create_edge_representation", "set_edge_tag"]
    assert _index(root).items[graph[2]].tags == {tag_id}


def test_second_tag_reuses_representation(
    root: Path, graph: tuple[UUID, UUID, UUID]
) -> None:
    t1 = tags.create_tag(_index(root), AUTHOR, "t1", "d", "node")
    tags.set_tag(_index(root), AUTHOR, t1, "e1")
    t2 = tags.create_tag(_index(root), AUTHOR, "t2", "d", "node")
    tags.set_tag(_index(root), AUTHOR, t2, "e1")
    tags.set_tag(_index(root), AUTHOR, t2, "e1")
    assert _meta_types(root).count("create_node_representation") == 1
    assert _meta_types(root).count("set_node_tag") == 3
    assert _index(root).items[graph[0]].tags == {t1, t2}


# --- set_tag rejections -----------------------------------------------------------


def test_unknown_tag(root: Path, graph: tuple[UUID, UUID, UUID]) -> None:
    with pytest.raises(UnknownItemError):
        tags.set_tag(_index(root), AUTHOR, str(uuid7()), "e1")
    assert _meta_types(root) == []


@pytest.mark.parametrize("source", ["e1", "m2"])
def test_source_must_be_a_tag(
    root: Path, graph: tuple[UUID, UUID, UUID], source: str
) -> None:
    tags.create_tag(_index(root), AUTHOR, "t", "d", "node")  # m1
    tags.set_tag(_index(root), AUTHOR, "m1", "e1")  # m2 representation, m3 meta edge
    before = _meta_types(root)
    with pytest.raises(ArchiveRuleError, match="is not a tag node"):
        tags.set_tag(_index(root), AUTHOR, source, "e1")
    assert _meta_types(root) == before


def test_only_the_tag_author(root: Path, graph: tuple[UUID, UUID, UUID]) -> None:
    tags.create_tag(_index(root), AUTHOR, "t", "d", "node")
    with pytest.raises(
        AuthorshipError, match="Only the tag's author may use this operation"
    ):
        tags.set_tag(_index(root), OTHER, "m1", "e1")
    assert _meta_types(root) == ["create_node_tag"]


def test_target_must_exist(root: Path) -> None:
    tags.create_tag(_index(root), AUTHOR, "t", "d", "node")
    with pytest.raises(UnknownItemError, match="UUID is not part of any network"):
        tags.set_tag(_index(root), AUTHOR, "m1", str(uuid7()))
    with pytest.raises(UnknownItemError, match="Unknown ID or alias"):
        tags.set_tag(_index(root), AUTHOR, "m1", "e7")
    assert _meta_types(root) == ["create_node_tag"]


def test_target_must_not_be_meta(root: Path) -> None:
    tags.create_tag(_index(root), AUTHOR, "t", "d", "node")
    with pytest.raises(
        ArchiveRuleError, match="should not be an item from the meta network"
    ):
        tags.set_tag(_index(root), AUTHOR, "m1", "m1")


@pytest.mark.parametrize(
    ("tag_kind", "target", "message"),
    [
        ("edge", "e1", "An edge tag should point to an edge representation"),
        ("node", "e3", "A node tag should point to a node representation"),
    ],
)
def test_kind_mismatch_keeps_representation_and_warns(
    root: Path,
    graph: tuple[UUID, UUID, UUID],
    caplog: pytest.LogCaptureFixture,
    tag_kind: Literal["node", "edge"],
    target: str,
    message: str,
) -> None:
    tags.create_tag(_index(root), AUTHOR, "t", "d", tag_kind)
    with (
        caplog.at_level(logging.WARNING, logger="indiek.ops.tags"),
        pytest.raises(ArchiveRuleError, match=message),
    ):
        tags.set_tag(_index(root), AUTHOR, "m1", target)
    target_kind = "node" if target == "e1" else "edge"
    assert _meta_types(root) == [
        f"create_{tag_kind}_tag",
        f"create_{target_kind}_representation",
    ]
    warnings = [r for r in caplog.records if r.name == "indiek.ops.tags"]
    assert len(warnings) == 1
    assert str(_index(root).aliases["m2"]) in warnings[0].getMessage()
    assert "remains in the meta log" in warnings[0].getMessage()


def test_no_warning_when_representation_existed(
    root: Path, graph: tuple[UUID, UUID, UUID], caplog: pytest.LogCaptureFixture
) -> None:
    tags.create_tag(_index(root), AUTHOR, "n", "d", "node")  # m1
    tags.set_tag(_index(root), AUTHOR, "m1", "e1")  # m2, m3
    tags.create_tag(_index(root), AUTHOR, "e", "d", "edge")  # m4
    before = _meta_types(root)
    with (
        caplog.at_level(logging.WARNING, logger="indiek.ops.tags"),
        pytest.raises(ArchiveRuleError, match="An edge tag should point to an edge"),
    ):
        tags.set_tag(_index(root), AUTHOR, "m4", "e1")
    assert _meta_types(root) == before
    assert not [r for r in caplog.records if r.name == "indiek.ops.tags"]
