"""SDK2:DROP-EDGE-DATA-REQUIREMENT: edges without content (format 3.1).

A content-less edge has ``resource_type: "none"`` and every other resource
field ``null``; only ``create_edge`` / ``supersede_edge`` bodies may use it,
and only in events whose header ``version`` is ``"3.1"``.  Writers stamp
``"3.1"`` on exactly those events, so archives without such edges stay 3.0.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from _builders import Builder
from pydantic import ValidationError

from indiek import Archive
from indiek.core.archive import ArchiveStore
from indiek.core.author import Author
from indiek.core.errors import IntegrityError
from indiek.core.index import ArchiveIndex
from indiek.core.models import (
    CONTENTLESS_FORMAT_VERSION,
    EVENT_FORMAT_VERSION,
    Edge,
    EventHeader,
    EventModel,
    MediaType,
    Node,
    ResourceType,
    SupersedeEdge,
)
from indiek.core.signing import sign_event
from indiek.ops import edges

AUTHOR = Author.from_seed_hex("78" * 32)  # public test vector, not a secret
RESOURCE_FIELDS = (
    "media_type",
    "blob_hash",
    "uri",
    "path",
    "file_size",
    "file_hash",
    "last_verified",
)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    return tmp_path / "archive"


@pytest.fixture
def two_nodes(root: Path) -> tuple[UUID, UUID]:
    build = Builder(root, AUTHOR)
    return build.node("source"), build.node("target")


def _index(root: Path) -> ArchiveIndex:
    return ArchiveIndex(ArchiveStore.open(root))


def _base_events(root: Path) -> list[dict[str, Any]]:
    return list(ArchiveStore.open(root).base_log)


def _rewrite_last_event(root: Path, edit: Any) -> None:
    """Apply ``edit`` to the last base event, re-sign it and write it back."""
    (log_file,) = sorted((root / "events").rglob("*ndjson"))
    lines = log_file.read_text(encoding="utf-8").splitlines()
    event = json.loads(lines[-1])
    edit(event)
    event["signature"] = sign_event(event, AUTHOR)
    lines[-1] = json.dumps(event, ensure_ascii=False)
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")


# --- models --------------------------------------------------------------------


def test_edge_accepts_resource_type_none() -> None:
    edge = Edge(
        resource_type=ResourceType.NONE,
        source_node=UUID(int=1),
        target_node=UUID(int=2),
    )
    assert all(getattr(edge, field) is None for field in RESOURCE_FIELDS)


@pytest.mark.parametrize(
    "extra",
    [
        {"media_type": MediaType.TEXT_PLAIN},
        {"blob_hash": "sha256:" + "0" * 64},
        {"uri": "https://example.org"},
        {"path": "/tmp/x"},
    ],
)
def test_resource_type_none_rejects_resource_fields(extra: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match="none resources"):
        Edge(
            resource_type=ResourceType.NONE,
            source_node=UUID(int=1),
            target_node=UUID(int=2),
            **extra,
        )


def test_nodes_cannot_be_content_less() -> None:
    with pytest.raises(ValidationError, match="only edges"):
        Node(resource_type=ResourceType.NONE)


def test_a_content_less_event_must_be_stamped_3_1() -> None:
    body = Edge(
        resource_type=ResourceType.NONE,
        source_node=UUID(int=1),
        target_node=UUID(int=2),
    )
    header = EventHeader(prev_hash=None, author=AUTHOR.public_key_hex)
    assert header.version == EVENT_FORMAT_VERSION == "3.0"
    with pytest.raises(ValidationError, match="3.1"):
        EventModel(header=header, body=body)
    header.version = CONTENTLESS_FORMAT_VERSION
    assert EventModel(header=header, body=body).header.version == "3.1"


# --- writing -------------------------------------------------------------------


def test_create_edge_without_content(root: Path, two_nodes: tuple[UUID, UUID]) -> None:
    edge_id = edges.create_edge(_index(root), AUTHOR, "e1", "e2")
    item = _index(root).get("e3")
    assert item.id == edge_id
    assert item.body["resource_type"] == "none"
    assert all(item.body[field] is None for field in RESOURCE_FIELDS)
    versions = [event["header"]["version"] for event in _base_events(root)]
    assert versions == ["3.0", "3.0", "3.1"]


def test_content_less_edge_writes_no_blob(
    root: Path, two_nodes: tuple[UUID, UUID]
) -> None:
    before = sorted(_index(root).store.blobs.iter_hashes())
    edges.create_edge(_index(root), AUTHOR, "e1", "e2", None)
    assert sorted(_index(root).store.blobs.iter_hashes()) == before


def test_supersede_edge_to_and_from_no_content(
    root: Path, two_nodes: tuple[UUID, UUID]
) -> None:
    edges.create_edge(_index(root), AUTHOR, "e1", "e2", "cites")
    edges.supersede_edge(_index(root), AUTHOR, "e3")
    assert _index(root).get("e3").body["resource_type"] == "none"
    edges.supersede_edge(_index(root), AUTHOR, "e3", "cites again")
    body = _index(root).get("e3").body
    assert (body["resource_type"], body["media_type"]) == (
        "managed",
        MediaType.TEXT_PLAIN.value,
    )
    versions = [event["header"]["version"] for event in _base_events(root)]
    assert versions == ["3.0", "3.0", "3.0", "3.1", "3.0"]


def test_supersede_body_with_none_keeps_endpoints() -> None:
    body = SupersedeEdge(
        edge_id=UUID(int=3),
        source_node=UUID(int=1),
        target_node=UUID(int=2),
        resource_type=ResourceType.NONE,
    )
    assert body.blob_hash is None and body.media_type is None


# --- facade: verify, seal, export ------------------------------------------------


def test_facade_full_cycle_with_a_content_less_edge(tmp_path: Path) -> None:
    ik = Archive.open(tmp_path / "ik", author=AUTHOR)
    a, b = ik.create_node("a"), ik.create_node("b")
    edge = ik.create_edge(a, b)
    tag = ik.create_tag("link", "untyped link", kind="edge")
    ik.set_tag(tag, edge)
    seal = ik.seal()
    assert ik.verify(expect=seal.hash) == seal
    assert ik.fsck().unreferenced_blobs == []
    reopened = Archive.open(tmp_path / "ik", verify="full")
    assert reopened.index.get("e3").body["resource_type"] == "none"
    meta_versions = {event["header"]["version"] for event in reopened.events("meta")}
    assert meta_versions == {"3.0"}


def test_export_handles_a_content_less_edge(tmp_path: Path) -> None:
    ik = Archive.open(tmp_path / "ik", author=AUTHOR)
    ik.create_edge(ik.create_node("a"), ik.create_node("b"))
    out = ik.export_graphml(tmp_path / "g.graphml")
    text = out.read_text(encoding="utf-8")
    graph = text.split("<graph ")[1]
    assert "<edge " in graph
    assert 'key="edge_label"' not in graph and 'key="edge_hash"' not in graph


# --- reading -------------------------------------------------------------------


def test_reader_accepts_3_1_on_any_event(
    root: Path, two_nodes: tuple[UUID, UUID]
) -> None:
    _rewrite_last_event(root, lambda e: e["header"].__setitem__("version", "3.1"))
    assert _index(root).get("e2").body["resource_type"] == "managed"


def test_reader_rejects_none_in_a_3_0_event(
    root: Path, two_nodes: tuple[UUID, UUID]
) -> None:
    edges.create_edge(_index(root), AUTHOR, "e1", "e2")
    _rewrite_last_event(root, lambda e: e["header"].__setitem__("version", "3.0"))
    with pytest.raises(IntegrityError, match="Invalid resource type 'none'"):
        _index(root)


def test_reader_rejects_none_on_a_node(
    root: Path, two_nodes: tuple[UUID, UUID]
) -> None:
    def make_node_content_less(event: dict[str, Any]) -> None:
        event["header"]["version"] = "3.1"
        event["body"].update(dict.fromkeys(RESOURCE_FIELDS), resource_type="none")

    _rewrite_last_event(root, make_node_content_less)
    with pytest.raises(IntegrityError, match="Invalid resource type 'none'"):
        _index(root)


def test_reader_rejects_none_with_resource_fields(
    root: Path, two_nodes: tuple[UUID, UUID]
) -> None:
    edges.create_edge(_index(root), AUTHOR, "e1", "e2")
    _rewrite_last_event(
        root, lambda e: e["body"].__setitem__("media_type", MediaType.TEXT_PLAIN.value)
    )
    with pytest.raises(IntegrityError, match="Invalid resource type 'none'"):
        _index(root)
