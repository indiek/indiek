"""Tests for ``ik create_edge``."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

import pytest

TEXT_PLAIN = "text/plain; charset=utf-8"


@pytest.fixture
def two_nodes(
    run_cli: Callable[..., None],
    base_events: Callable[[], list[dict[str, Any]]],
) -> tuple[str, str]:
    """Create two managed nodes and return their UUIDs in creation order."""
    run_cli("create_node", "--content", "source node")
    run_cli("create_node", "--content", "target node")
    events = base_events()
    return events[0]["body"]["node_id"], events[1]["body"]["node_id"]


def test_create_edge_by_uuid(
    run_cli: Callable[..., None],
    base_events: Callable[[], list[dict[str, Any]]],
    blob_paths: Callable[[], list[Path]],
    author_public_key: str,
    two_nodes: tuple[str, str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    source, target = two_nodes
    run_cli(
        "create_edge",
        "--content",
        "implies",
        "--source-node",
        source,
        "--target-node",
        target,
    )

    events = base_events()
    assert len(events) == 3
    body = events[-1]["body"]
    assert body["event_type"] == "create_edge"
    assert body["body_type"] == "edge"
    assert body["source_node"] == source
    assert body["target_node"] == target
    assert body["resource_type"] == "managed"
    # create_edge always writes its content as plain text.
    assert body["media_type"] == TEXT_PLAIN
    assert events[-1]["header"]["author"] == author_public_key

    edge_blob = next(path for path in blob_paths() if path.read_bytes() == b"implies")
    assert edge_blob.name == body["blob_hash"].removeprefix("sha256:")
    assert f"Edge created: {body['edge_id']}" in capsys.readouterr().out


def test_create_edge_resolves_human_friendly_aliases(
    run_cli: Callable[..., None],
    base_events: Callable[[], list[dict[str, Any]]],
    two_nodes: tuple[str, str],
) -> None:
    source, target = two_nodes
    # Base-network creation events are aliased e1, e2, ... in log order.
    run_cli(
        "create_edge",
        "--content",
        "cites",
        "--source-node",
        "e1",
        "--target-node",
        "e2",
    )

    body = base_events()[-1]["body"]
    assert body["source_node"] == source
    assert body["target_node"] == target


def test_create_edge_alias_numbering_includes_edges(
    run_cli: Callable[..., None],
    base_events: Callable[[], list[dict[str, Any]]],
    two_nodes: tuple[str, str],
) -> None:
    """The alias counter is shared by nodes and edges, so the first edge is e3."""
    run_cli(
        "create_edge",
        "--content",
        "first",
        "--source-node",
        "e1",
        "--target-node",
        "e2",
    )
    run_cli("create_node", "--content", "third node")
    run_cli(
        "create_edge",
        "--content",
        "second",
        "--source-node",
        "e4",
        "--target-node",
        "e2",
    )

    events = base_events()
    second_node_id = events[1]["body"]["node_id"]
    third_node_id = events[3]["body"]["node_id"]
    last = events[-1]["body"]
    assert last["source_node"] == third_node_id
    assert last["target_node"] == second_node_id


def test_create_edge_self_loop_is_allowed(
    run_cli: Callable[..., None],
    base_events: Callable[[], list[dict[str, Any]]],
    two_nodes: tuple[str, str],
) -> None:
    source, _ = two_nodes
    run_cli(
        "create_edge", "--content", "self", "--source-node", "e1", "--target-node", "e1"
    )

    body = base_events()[-1]["body"]
    assert body["source_node"] == body["target_node"] == source


def test_create_edge_rejects_unknown_alias(
    run_cli: Callable[..., None],
    base_events: Callable[[], list[dict[str, Any]]],
    two_nodes: tuple[str, str],
) -> None:
    with pytest.raises(ValueError):
        run_cli(
            "create_edge",
            "--content",
            "dangling",
            "--source-node",
            "e1",
            "--target-node",
            "e99",
        )
    # The failed command appended no event.
    assert len(base_events()) == 2


@pytest.mark.parametrize(
    "missing",
    ["--content", "--source-node", "--target-node"],
)
def test_create_edge_requires_all_three_flags(
    run_cli: Callable[..., None],
    two_nodes: tuple[str, str],
    missing: str,
) -> None:
    argv = {
        "--content": "text",
        "--source-node": "e1",
        "--target-node": "e2",
    }
    argv.pop(missing)
    flat = [item for pair in argv.items() for item in pair]
    with pytest.raises(SystemExit) as excinfo:
        run_cli("create_edge", *flat)
    assert excinfo.value.code == 2


def test_create_edge_chains_onto_the_existing_log(
    run_cli: Callable[..., None],
    base_events: Callable[[], list[dict[str, Any]]],
    two_nodes: tuple[str, str],
) -> None:
    run_cli(
        "create_edge",
        "--content",
        "links",
        "--source-node",
        "e1",
        "--target-node",
        "e2",
    )

    events = base_events()
    assert events[-1]["header"]["prev_hash"] is not None
    # Every event but genesis records a predecessor; the chain is verified on
    # the next CLI invocation, which would raise IntegrityError if broken.
    run_cli("create_node", "--content", "after the edge")
    assert len(base_events()) == 4
