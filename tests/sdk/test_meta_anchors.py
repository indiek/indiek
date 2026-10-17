"""Meta events anchor to the base log (CLIPYPI:META-ANCHORS, seal.md A).

"Meta commits to base, base never commits to meta": every meta event header
carries ``base_seq`` (number of base events the author had verified) and
``base_head`` (hash of base event number ``base_seq``; ``null`` iff 0).
Owner decision D7 (2026-10-17): ``base_seq`` never decreases along the meta
log.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from _builders import Builder
from pydantic import ValidationError

from indiek import Archive, Author, IntegrityError
from indiek.core.archive import verify_chain
from indiek.core.models import MetaEventHeader, MetaEventType, Tag
from indiek.core.storage import BlobStore, EventLog

ALICE = Author.from_seed_hex("a1" * 32)  # public test vectors, not secrets
BOB = Author.from_seed_hex("b0" * 32)
MISMATCH = "Meta anchor does not match base history"


@pytest.fixture
def root(tmp_path: Path) -> Path:
    return tmp_path / "archive"


def _headers(ik: Archive) -> list[dict[str, object]]:
    return [event["header"] for event in ik.events("meta")]


def _base_alone_verifies(root: Path) -> bool:
    state = verify_chain(EventLog(root / "events"), BlobStore(root))
    return state.count > 0


def _tag(name: str) -> Tag:
    return Tag(name=name, description="d", event_type=MetaEventType.CREATE_NODE_TAG)


# -- what gets written ------------------------------------------------------------


def test_meta_events_anchor_to_the_base_tip(root: Path) -> None:
    ik = Archive.open(root, author=ALICE)
    ik.create_tag("early", "before any base event", kind="node")  # anchor 0
    ik.create_node("a")
    ik.create_node("b")
    head_after_two = ik.head
    ik.create_tag("t", "d", kind="node")  # anchor 2
    ik.set_tag("m2", "e2")  # representation + assignment, anchor 2
    ik.create_node("c")
    ik.transcribe(network="meta")  # anchor 3: meta transcriptions are anchored too

    anchors = [(h["base_seq"], h["base_head"]) for h in _headers(ik)]
    assert anchors == [
        (0, None),
        (2, head_after_two),
        (2, head_after_two),
        (2, head_after_two),
        (3, ik.head),
    ]
    assert Archive.open(root).meta_head == ik.meta_head  # and it all verifies


def test_base_events_never_mention_the_meta_log(root: Path) -> None:
    ik = Archive.open(root, author=ALICE)
    ik.create_tag("t", "d", kind="node")
    ik.create_node("a")
    for event in ik.events("base"):
        assert not {"base_seq", "base_head"} & event["header"].keys()


def test_base_writes_leave_the_meta_log_untouched(root: Path) -> None:
    ik = Archive.open(root, author=ALICE)
    ik.create_node("a")
    ik.create_tag("t", "d", kind="node")
    (meta_file,) = (root / "meta" / "events").rglob("*ndjson")
    before = meta_file.read_bytes()
    ik.create_node("b")
    ik.supersede_node("e1", "a2")
    assert meta_file.read_bytes() == before


@pytest.mark.parametrize(
    ("base_seq", "base_head"),
    [(0, "sha256:" + "ab" * 32), (1, None), (-1, None)],
    ids=["zero-with-head", "positive-without-head", "negative"],
)
def test_the_header_model_rejects_inconsistent_anchors(
    base_seq: int, base_head: str | None
) -> None:
    with pytest.raises(ValidationError):
        MetaEventHeader(
            prev_hash=None,
            author=ALICE.public_key_hex,
            base_seq=base_seq,
            base_head=base_head,
        )


# -- what verification catches ----------------------------------------------------


def test_a_rewritten_base_breaks_the_meta_anchors(root: Path) -> None:
    alice = Archive.open(root, author=ALICE)
    for text in ("a", "b", "c"):
        alice.create_node(text)
    Archive.open(root, author=BOB).create_tag("t", "Bob's annotation", kind="node")

    # Alice forks her history: same length, validly re-signed, different content.
    shutil.rmtree(root / "events")
    forger = Builder(root, ALICE)
    for text in ("a", "B!", "c"):
        forger.node(text)

    assert _base_alone_verifies(root)
    with pytest.raises(IntegrityError, match=MISMATCH):
        Archive.open(root)


def test_a_truncated_base_breaks_the_meta_anchors(root: Path) -> None:
    ik = Archive.open(root, author=ALICE)
    for text in ("a", "b", "c"):
        ik.create_node(text)
    ik.create_tag("t", "d", kind="node")  # anchored at 3

    (base_file,) = (root / "events").rglob("*ndjson")
    lines = base_file.read_text("utf-8").splitlines(keepends=True)
    base_file.write_text("".join(lines[:2]), encoding="utf-8")

    assert _base_alone_verifies(root)
    with pytest.raises(IntegrityError, match=MISMATCH):
        Archive.open(root)


def test_an_anchor_to_the_wrong_head_is_rejected(root: Path) -> None:
    build = Builder(root, ALICE)
    build.node("a")
    build.node("b")
    build.raw_meta(_tag("t"), anchor=(2, build.base_hashes[0]))
    with pytest.raises(IntegrityError, match=MISMATCH):
        Archive.open(root)


def test_an_anchor_beyond_the_base_is_rejected(root: Path) -> None:
    build = Builder(root, ALICE)
    build.node("a")
    build.raw_meta(_tag("t"), anchor=(2, "sha256:" + "ab" * 32))
    with pytest.raises(IntegrityError, match=MISMATCH):
        Archive.open(root)


def test_an_anchor_going_backwards_is_rejected(root: Path) -> None:
    """Owner decision D7: base_seq is non-decreasing along the meta log."""
    build = Builder(root, ALICE)
    build.node("a")
    build.node("b")
    build.raw_meta(_tag("t1"))  # anchored at 2
    build.raw_meta(_tag("t2"), anchor=(1, build.base_hashes[0]))  # truthful, but older
    with pytest.raises(IntegrityError, match="Meta anchor goes back in base history"):
        Archive.open(root)


def test_an_edited_anchor_breaks_the_signature(root: Path) -> None:
    ik = Archive.open(root, author=ALICE)
    ik.create_node("a")
    ik.create_node("b")
    ik.create_tag("t", "d", kind="node")
    (meta_file,) = (root / "meta" / "events").rglob("*ndjson")
    event = json.loads(meta_file.read_text("utf-8"))
    event["header"]["base_seq"] = 1
    event["header"]["base_head"] = ik.index.store.base.hashes[0]  # a truthful anchor
    meta_file.write_text(json.dumps(event, ensure_ascii=False) + "\n", "utf-8")
    with pytest.raises(IntegrityError, match="Data tampered or bad author!"):
        Archive.open(root)


# -- separation of the two networks -------------------------------------------------


def test_the_base_ships_and_verifies_without_the_meta_log(root: Path) -> None:
    ik = Archive.open(root, author=ALICE)
    ik.create_node("a")
    ik.create_tag("t", "d", kind="node")
    ik.set_tag("m1", "e1")
    head = ik.head
    shutil.rmtree(root / "meta")
    alone = Archive.open(root)
    assert (alone.head, alone.meta_head) == (head, None)
    assert alone.index.get("e1").tags == set()


def test_another_key_may_annotate_someone_elses_base(root: Path) -> None:
    alice = Archive.open(root, author=ALICE)
    node = alice.create_node("Alice's claim")
    bob = Archive.open(root, author=BOB)
    tag = bob.create_tag("doubtful", "Bob doubts it", kind="node")
    bob.set_tag(tag, node)

    reopened = Archive.open(root)
    assert reopened.index.items[node].tags == {tag}
    assert {h["author"] for h in _headers(reopened)} == {BOB.public_key_hex}
    assert {h["base_head"] for h in _headers(reopened)} == {alice.head}
