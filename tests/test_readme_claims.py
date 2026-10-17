"""Checks for README claims about read/export/ingest/manifest/config/supersede."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from indiek import cli as ik_cli


def _creates(events: list[dict]) -> list[dict]:
    """Creation events in alias order (e1, e2, ... or m1, m2, ...)."""
    return [e for e in events if e["body"]["event_type"].startswith(("create", "set"))]


def test_lowercase_logging_level_is_accepted(archive_root, author_seed_hex, monkeypatch):
    monkeypatch.setenv("IK_ARCHIVE_PATH", str(archive_root))
    monkeypatch.setenv("IK_AUTHOR_PRIVATE_KEY", author_seed_hex)
    monkeypatch.setattr("sys.argv", ["ik", "--logging-level", "debug", "read"])
    ik_cli.main()
    assert logging.getLogger().level == logging.DEBUG


def test_config_bootstraps_without_archive_path_or_key(archive_root, monkeypatch):
    monkeypatch.delenv("IK_ARCHIVE_PATH", raising=False)
    monkeypatch.delenv("IK_AUTHOR_PRIVATE_KEY", raising=False)
    dotenv = archive_root.parent / "cfg.env"
    monkeypatch.setattr(
        "sys.argv",
        ["ik", "--dot-env", str(dotenv), "config", "--set-archive-path", "/x"],
    )
    ik_cli.main()
    assert dotenv.read_text(encoding="utf-8").strip() == "IK_ARCHIVE_PATH='/x'"


def test_config_writes_quoted_path(archive_root, author_seed_hex, monkeypatch):
    dotenv = archive_root.parent / "cfg.env"
    dotenv.write_text("", encoding="utf-8")
    monkeypatch.setenv("IK_ARCHIVE_PATH", str(archive_root))
    monkeypatch.setenv("IK_AUTHOR_PRIVATE_KEY", author_seed_hex)
    monkeypatch.setattr(
        "sys.argv",
        ["ik", "--dot-env", str(dotenv), "config", "--set-archive-path", "/x/y"],
    )
    ik_cli.main()
    assert dotenv.read_text(encoding="utf-8").strip() == "IK_ARCHIVE_PATH='/x/y'"


def test_supersede_node_keeps_title_any_author(run_cli, base_events, other_author):
    run_cli("create_node", "--content", "v1", "--title", "T")
    run_cli(
        "supersede_node", "--node-id", "e1", "--content", "v2", seed_hex=other_author[0]
    )
    last = base_events()[-1]
    assert last["body"]["event_type"] == "supersede_node"
    assert last["body"]["title"] == "T"
    assert last["body"]["media_type"].startswith("text/markdown")
    assert last["header"]["author"] == other_author[1]


def test_supersede_edge_keeps_endpoints(run_cli, base_events):
    run_cli("create_node", "--content", "a")
    run_cli("create_node", "--content", "b")
    run_cli(
        "create_edge", "--source-node", "e1", "--target-node", "e2", "--content", "r"
    )
    run_cli("supersede_edge", "--edge-id", "e3", "--content", "r2")
    edge, sup = base_events()[2]["body"], base_events()[3]["body"]
    assert (sup["source_node"], sup["target_node"]) == (
        edge["source_node"],
        edge["target_node"],
    )
    assert sup["media_type"].startswith("text/plain")


def test_supersede_rejects_wrong_kind(run_cli):
    run_cli("create_node", "--content", "a")
    with pytest.raises(ValueError, match="does not reference a base-network edge"):
        run_cli("supersede_edge", "--edge-id", "e1", "--content", "x")


def test_ingest_keeps_newline_and_stores_subdir_path(
    run_cli, base_events, tmp_path, archive_root
):
    folder = tmp_path / "in"
    (folder / "sub").mkdir(parents=True)
    (folder / "a.txt").write_text("alpha", encoding="utf-8")
    edges = tmp_path / "edges.csv"
    edges.write_text("e1,e2,x, y\n", encoding="utf-8")
    run_cli("ingest", "--input-folder", str(folder), "--edges-def-file", str(edges))
    events = base_events()
    assert [e["body"]["event_type"] for e in events] == [
        "create_node",
        "create_node",
        "create_edge",
    ]
    assert events[1]["body"]["title"] == "sub"
    blob = events[2]["body"]["blob_hash"].split(":")[1]
    path = archive_root / "blobs" / "sha256" / blob[:2] / blob[2:4] / blob
    assert path.read_bytes().decode("utf-8") == "x, y\n"


def test_export_tags_is_or(run_cli, tmp_path):
    for c in ("a", "b", "c"):
        run_cli("create_node", "--content", c)
    run_cli("create_node_tag", "--name", "t1", "--description", "d")  # m1
    run_cli("create_node_tag", "--name", "t2", "--description", "d")  # m2
    run_cli("set_tag", "--tag", "m1", "--id", "e1")
    run_cli("set_tag", "--tag", "m2", "--id", "e2")
    out = tmp_path / "g.graphml"
    run_cli("export", "--output-path", str(out), "--tags", "m1,m2")
    xml = out.read_text(encoding="utf-8")
    assert xml.count("<node ") == 2


def test_manifest_written(run_cli, archive_root, author_public_key):
    run_cli("manifest")
    data = json.loads((archive_root / "MANIFEST.json").read_text(encoding="utf-8"))
    assert data["authors"] == [
        {"public_key": author_public_key, "algorithm": "Ed25519"}
    ]


def test_readme_walkthrough_aliases(
    run_cli, base_events, meta_events, sample_files, tmp_path
):
    s = sample_files
    run_cli("create_node", "--content", "Gödel")
    run_cli("create_node", "--content", str(s["plain"]))
    run_cli("create_node", "--content", str(s["markdown"]), "--title", "Proof")
    run_cli("create_node", "--content", str(s["png"]))
    run_cli(
        "create_node",
        "--resource-type",
        "uri",
        "--uri",
        "https://x.org",
        "--media-type",
        "application/pdf; profile=pdfa",
    )
    run_cli("create_node", "--resource-type", "local_file", "--path", str(s["png"]))
    run_cli(
        "create_edge",
        "--source-node",
        "e2",
        "--target-node",
        "e1",
        "--content",
        "states",
    )
    run_cli(
        "create_edge",
        "--source-node",
        "e3",
        "--target-node",
        "e2",
        "--content",
        "proves",
    )
    run_cli("supersede_node", "--node-id", "e1", "--content", "Gödel 1st")
    run_cli("supersede_edge", "--edge-id", "e8", "--content", "sketches")
    run_cli("create_node_tag", "--name", "theorem", "--description", "d")
    run_cli("create_edge_tag", "--name", "proof", "--description", "d")
    run_cli("set_tag", "--tag", "m1", "--id", "e1")
    run_cli("set_tag", "--tag", "m2", "--id", "e8")
    more = tmp_path / "more"
    more.mkdir()
    (more / "c.txt").write_text("cite", encoding="utf-8")
    edges = tmp_path / "edges.csv"
    edges.write_text("e9,e1,cites\n", encoding="utf-8")
    run_cli("ingest", "--input-folder", str(more), "--edges-def-file", str(edges))
    run_cli("read", "--mini")
    run_cli("export", "--output-path", str(tmp_path / "t.graphml"), "--tags", "m1,m2")
    run_cli("manifest")

    base = _creates(base_events())
    assert len(base) == 10
    assert base[1]["body"]["title"] == "note"
    assert base[7]["body"]["event_type"] == "create_edge"
    meta = [e["body"]["event_type"] for e in _creates(meta_events())]
    assert meta == [
        "create_node_tag",
        "create_edge_tag",
        "create_node_representation",
        "set_node_tag",
        "create_edge_representation",
        "set_edge_tag",
    ]
    assert Path(tmp_path / "t.graphml").exists()
