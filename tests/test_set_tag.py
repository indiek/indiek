"""Tests for ``ik set_tag``."""

from __future__ import annotations

import logging
from typing import Any, Callable, Literal
from uuid import uuid4

import pytest


def _make_tag(
    run_cli: Callable[..., None],
    name: str = "topology",
    kind: Literal["node", "edge"] = "node",
) -> None:
    run_cli(f"create_{kind}_tag", "--name", name, "--description", f"About {name}")


def test_tagging_a_node_creates_representation_then_meta_edge(
    run_cli: Callable[..., None],
    base_events: Callable[[], list[dict[str, Any]]],
    meta_events: Callable[[], list[dict[str, Any]]],
) -> None:
    run_cli("create_node", "--content", "a node")
    _make_tag(run_cli)
    run_cli("set_tag", "--tag", "m1", "--id", "e1")

    node_id = base_events()[0]["body"]["node_id"]
    events = meta_events()
    assert len(events) == 3
    tag, representation, meta_edge = (event["body"] for event in events)

    assert representation["event_type"] == "create_node_representation"
    assert representation["underlying_id"] == node_id

    assert meta_edge["event_type"] == "set_node_tag"
    assert meta_edge["body_type"] == "edge"
    assert meta_edge["source_node"] == tag["node_id"]
    assert meta_edge["target_node"] == representation["node_id"]

    # The meta chain links every new event; the base log is untouched.
    assert all(event["header"]["prev_hash"] for event in events[1:])
    assert len(base_events()) == 1


def test_set_tag_accepts_full_uuids(
    run_cli: Callable[..., None],
    base_events: Callable[[], list[dict[str, Any]]],
    meta_events: Callable[[], list[dict[str, Any]]],
) -> None:
    run_cli("create_node", "--content", "a node")
    _make_tag(run_cli)
    node_id = base_events()[0]["body"]["node_id"]
    tag_id = meta_events()[0]["body"]["node_id"]

    run_cli("set_tag", "--tag", tag_id, "--id", node_id)

    events = meta_events()
    assert len(events) == 3
    assert events[1]["body"]["underlying_id"] == node_id
    assert events[2]["body"]["source_node"] == tag_id


def test_second_tag_reuses_existing_representation(
    run_cli: Callable[..., None],
    meta_events: Callable[[], list[dict[str, Any]]],
) -> None:
    run_cli("create_node", "--content", "a node")
    _make_tag(run_cli, "first")  # m1
    run_cli("set_tag", "--tag", "m1", "--id", "e1")  # m2 representation, m3 edge
    _make_tag(run_cli, "second")  # m4
    run_cli("set_tag", "--tag", "m4", "--id", "e1")  # m5 edge only

    bodies = [event["body"] for event in meta_events()]
    assert len(bodies) == 5
    representations = [
        body for body in bodies if body["event_type"] == "create_node_representation"
    ]
    assert len(representations) == 1
    meta_edges = [body for body in bodies if body["event_type"] == "set_node_tag"]
    assert len(meta_edges) == 2
    assert {edge["target_node"] for edge in meta_edges} == {
        representations[0]["node_id"]
    }


def test_tagging_an_edge_uses_edge_representation(
    run_cli: Callable[..., None],
    base_events: Callable[[], list[dict[str, Any]]],
    meta_events: Callable[[], list[dict[str, Any]]],
) -> None:
    run_cli("create_node", "--content", "source")  # e1
    run_cli("create_node", "--content", "target")  # e2
    run_cli(
        "create_edge",
        "--source-node",
        "e1",
        "--target-node",
        "e2",
        "--content",
        "links",
    )
    _make_tag(run_cli, kind="edge")
    run_cli("set_tag", "--tag", "m1", "--id", "e3")

    node_ids = {event["body"].get("node_id") for event in base_events()[:2]}
    bodies = [event["body"] for event in meta_events()]
    assert [body["event_type"] for body in bodies[1:]] == [
        "create_edge_representation",
        "set_edge_tag",
    ]
    assert bodies[1]["underlying_id"] not in node_ids
    assert bodies[2]["target_node"] == bodies[1]["node_id"]


@pytest.mark.parametrize(
    ("tag_kind", "target", "message"),
    [
        ("edge", "e1", "An edge tag should point to an edge representation"),
        ("node", "e3", "A node tag should point to a node representation"),
    ],
)
def test_tag_kind_must_match_target_kind(
    run_cli: Callable[..., None],
    meta_events: Callable[[], list[dict[str, Any]]],
    caplog: pytest.LogCaptureFixture,
    tag_kind: Literal["node", "edge"],
    target: str,
    message: str,
) -> None:
    run_cli("create_node", "--content", "source")  # e1
    run_cli("create_node", "--content", "target")  # e2
    run_cli(
        "create_edge",
        "--source-node",
        "e1",
        "--target-node",
        "e2",
        "--content",
        "links",
    )  # e3
    _make_tag(run_cli, kind=tag_kind)  # m1

    with (
        caplog.at_level(logging.WARNING, logger="indiek.set_tag"),
        pytest.raises(ValueError, match=message),
    ):
        run_cli("set_tag", "--tag", "m1", "--id", target)

    # Intended behaviour: the representation is appended before the kind check
    # runs, so a rejected set_tag leaves it in the meta log and warns the user.
    # No meta edge is written.
    bodies = [event["body"] for event in meta_events()]
    assert [body["event_type"] for body in bodies] == [
        f"create_{tag_kind}_tag",
        f"create_{'node' if target == 'e1' else 'edge'}_representation",
    ]
    warnings = [
        record
        for record in caplog.records
        if record.name == "indiek.set_tag" and record.levelno == logging.WARNING
    ]
    assert len(warnings) == 1
    assert bodies[1]["node_id"] in warnings[0].getMessage()
    assert "remains in the meta log" in warnings[0].getMessage()


def test_no_warning_when_rejected_target_already_has_representation(
    run_cli: Callable[..., None],
    meta_events: Callable[[], list[dict[str, Any]]],
    caplog: pytest.LogCaptureFixture,
) -> None:
    run_cli("create_node", "--content", "a node")  # e1
    _make_tag(run_cli, "first", kind="node")  # m1
    run_cli("set_tag", "--tag", "m1", "--id", "e1")  # m2 representation, m3 edge
    _make_tag(run_cli, "second", kind="edge")  # m4
    before = len(meta_events())

    with (
        caplog.at_level(logging.WARNING, logger="indiek.set_tag"),
        pytest.raises(ValueError, match="An edge tag should point to an edge"),
    ):
        run_cli("set_tag", "--tag", "m4", "--id", "e1")

    assert len(meta_events()) == before
    assert not [
        record
        for record in caplog.records
        if record.name == "indiek.set_tag" and record.levelno == logging.WARNING
    ]


@pytest.mark.parametrize("source", ["e1", "m2"])
def test_source_must_be_a_tag(
    run_cli: Callable[..., None],
    meta_events: Callable[[], list[dict[str, Any]]],
    source: str,
) -> None:
    run_cli("create_node", "--content", "a node")  # e1
    _make_tag(run_cli)  # m1
    run_cli("set_tag", "--tag", "m1", "--id", "e1")  # m2 is a representation
    before = len(meta_events())

    with pytest.raises(ValueError, match="is not a tag node"):
        run_cli("set_tag", "--tag", source, "--id", "e1")
    assert len(meta_events()) == before


def test_target_must_not_be_a_meta_item(
    run_cli: Callable[..., None],
    meta_events: Callable[[], list[dict[str, Any]]],
) -> None:
    _make_tag(run_cli)

    with pytest.raises(ValueError, match="should not be an item from the meta network"):
        run_cli("set_tag", "--tag", "m1", "--id", "m1")
    assert len(meta_events()) == 1


def test_target_must_exist(
    run_cli: Callable[..., None],
    meta_events: Callable[[], list[dict[str, Any]]],
) -> None:
    _make_tag(run_cli)

    with pytest.raises(ValueError, match="not part of any network"):
        run_cli("set_tag", "--tag", "m1", "--id", str(uuid4()))
    assert len(meta_events()) == 1


def test_only_the_tag_author_may_use_it(
    run_cli: Callable[..., None],
    meta_events: Callable[[], list[dict[str, Any]]],
    other_author: tuple[str, str],
) -> None:
    run_cli("create_node", "--content", "a node")
    _make_tag(run_cli)

    with pytest.raises(ValueError, match="Only the tag's author"):
        run_cli("set_tag", "--tag", "m1", "--id", "e1", seed_hex=other_author[0])
    assert len(meta_events()) == 1


@pytest.mark.parametrize("missing", ["--tag", "--id"])
def test_set_tag_requires_tag_and_id(
    run_cli: Callable[..., None],
    missing: str,
) -> None:
    argv = {"--tag": "m1", "--id": "e1"}
    argv.pop(missing)
    flat = [item for pair in argv.items() for item in pair]
    with pytest.raises(SystemExit) as excinfo:
        run_cli("set_tag", *flat)
    assert excinfo.value.code == 2
