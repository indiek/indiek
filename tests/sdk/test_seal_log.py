"""The signed seal log (CLIPYPI:SEAL-LOG, seal.md B).

A seal commits to the base tip, the meta tip and the Merkle root of the blob
store; seals form their own hash chain in ``seals/seals.ndjson``.  The latest
seal hash is the one string that commits to the whole archive.

Owner decisions 2026-10-17: D9 RFC 6962 blob root; D10 ``seq`` = position
from 1 and tip counts never decrease; D11 any key may seal, empty or
unchanged archives are refused on write; D11b such seals only WARN on read.
Option C: ``blob_root`` covers the blobs referenced by the events a seal
covers; every seal is checked exactly; files no event references block
sealing and only WARN on read.
"""

from __future__ import annotations

import json
import logging
import shutil
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest
from _builders import Builder

from indiek import (
    Archive,
    ArchiveRuleError,
    Author,
    AuthorshipError,
    IntegrityError,
    Seal,
)
from indiek.core.archive import ArchiveStore
from indiek.core.canonical import canonical_bytes, digest
from indiek.core.merkle import blob_root
from indiek.core.models import LogTip, SealModel
from indiek.core.signing import sign_object, verify_object
from indiek.core.storage import SealLog

ALICE = Author.from_seed_hex("5a" * 32)  # public test vectors, not secrets
BOB = Author.from_seed_hex("5b" * 32)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    return tmp_path / "archive"


@pytest.fixture
def ik(root: Path) -> Archive:
    return Archive.open(root, author=ALICE)


def _seal_lines(root: Path) -> list[dict[str, Any]]:
    path = root / "seals" / "seals.ndjson"
    return [json.loads(line) for line in path.read_text("utf-8").splitlines()]


def _write_seal_lines(root: Path, seals: list[dict[str, Any]]) -> None:
    path = root / "seals" / "seals.ndjson"
    path.write_text(
        "".join(json.dumps(s, ensure_ascii=False) + "\n" for s in seals), "utf-8"
    )


def _forge(
    root: Path,
    author: Author = ALICE,
    *,
    seq: int | None = None,
    base: LogTip | None = None,
    meta: LogTip | None = None,
    root_hash: str | None = None,
) -> None:
    """Append a validly signed seal built from the verified state, with overrides."""
    store = ArchiveStore.open(root)
    model = SealModel(
        seq=seq if seq is not None else store.seals.count + 1,
        prev_seal_hash=store.seals.head,
        base=base or LogTip(head=store.base.head, count=store.base.count),
        meta=meta or LogTip(head=store.meta.head, count=store.meta.count),
        blob_root=root_hash or blob_root(store.referenced_blobs),
        key=author.public_key_hex,
    )
    model.sig = sign_object(model, author, "sig")
    SealLog(root / "seals").append(model)


def _populate(ik: Archive) -> None:
    ik.create_node("a")
    ik.create_node("b")
    ik.create_edge("e1", "e2", "ab")
    ik.create_tag("t", "d", kind="node")


# -- sealing --------------------------------------------------------------------


def test_seal_commits_to_both_tips_and_the_blob_root(ik: Archive, root: Path) -> None:
    _populate(ik)
    seal = ik.seal()

    assert isinstance(seal, Seal)
    assert (seal.seq, seal.prev_seal_hash, seal.key) == (1, None, ALICE.public_key_hex)
    assert (seal.base_head, seal.base_count) == (ik.head, 3)
    assert (seal.meta_head, seal.meta_count) == (ik.meta_head, 1)
    assert seal.blob_root == blob_root(ik.index.store.blobs.iter_hashes())
    assert seal.time.tzinfo is not None

    (line,) = _seal_lines(root)
    assert (line["type"], line["version"]) == ("seal", "3.0")
    assert (line["hash_alg"], line["sig_alg"]) == ("sha256", "ed25519")
    assert line["sig"].startswith("ed25519:")
    assert seal.hash == digest(canonical_bytes(line))
    assert seal.hash.startswith("sha256:")


def test_seals_chain_and_persist(ik: Archive, root: Path) -> None:
    _populate(ik)
    first = ik.seal()
    ik.create_node("c")
    second = ik.seal()
    assert (second.seq, second.prev_seal_hash) == (2, first.hash)
    assert ik.seals() == [first, second]
    assert Archive.open(root).seals() == [first, second]


def test_an_archive_without_seals_has_none(ik: Archive) -> None:
    ik.create_node("a")
    assert ik.seals() == []
    assert ik.verify() is None


def test_sealing_an_empty_archive_is_refused(ik: Archive, root: Path) -> None:
    with pytest.raises(ArchiveRuleError, match="Nothing to seal: the archive is empty"):
        ik.seal()
    assert not (root / "seals").exists()


def test_sealing_an_unchanged_archive_is_refused(ik: Archive) -> None:
    _populate(ik)
    ik.seal()
    with pytest.raises(
        ArchiveRuleError, match="Nothing to seal: the archive is unchanged since seal 1"
    ):
        ik.seal()
    assert len(ik.seals()) == 1


@pytest.mark.parametrize("change", ["base", "meta"])
def test_any_change_allows_a_new_seal(ik: Archive, change: str) -> None:
    _populate(ik)
    ik.seal()
    if change == "meta":
        ik.create_tag("t2", "d", kind="edge")
    else:
        ik.supersede_node("e1", "a2")
    assert ik.seal().seq == 2


def test_any_key_may_seal_but_a_key_is_required(ik: Archive, root: Path) -> None:
    _populate(ik)
    with pytest.raises(AuthorshipError, match="An author is required"):
        Archive.open(root).seal()
    assert Archive.open(root, author=BOB).seal().key == BOB.public_key_hex


def test_unreferenced_blobs_block_sealing_until_deleted(
    ik: Archive, root: Path
) -> None:
    _populate(ik)
    stray = ik.index.store.blobs.put("left behind by an interrupted write")
    ik.refresh()
    (path,) = ik.unreferenced_blobs()
    assert path.name == stray
    with pytest.raises(ArchiveRuleError, match="Cannot seal: 1 unreferenced blob") as e:
        ik.seal()
    assert str(path) in str(e.value)
    assert not (root / "seals").exists()

    path.unlink()  # safe: no event uses it
    assert ik.seal().seq == 1
    assert ik.unreferenced_blobs() == []


def test_unreferenced_blobs_are_reported_on_open(
    ik: Archive, root: Path, caplog: pytest.LogCaptureFixture
) -> None:
    _populate(ik)
    stray = ik.index.store.blobs.put("hand-added file")
    with caplog.at_level(logging.WARNING, logger="indiek.core.archive"):
        Archive.open(root)
    (record,) = [r for r in caplog.records if r.name == "indiek.core.archive"]
    assert "1 unreferenced blob" in record.getMessage()
    assert stray in record.getMessage()


# -- verify(expect=...) ---------------------------------------------------------


def test_verify_returns_the_latest_or_the_expected_seal(ik: Archive) -> None:
    _populate(ik)
    first = ik.seal()
    ik.create_node("c")
    second = ik.seal()
    assert ik.verify() == second
    assert ik.verify(expect=first.hash) == first


def test_verify_rejects_an_unknown_expected_seal(ik: Archive) -> None:
    _populate(ik)
    ik.seal()
    with pytest.raises(IntegrityError, match="Expected seal not found in seal log"):
        ik.verify(expect="sha256:" + "00" * 32)


def test_verify_rereads_the_disk(ik: Archive, root: Path) -> None:
    _populate(ik)
    ik.seal()
    blob = ik.index.get("e1").body["blob_hash"]
    ik.index.store.blobs.path_for(blob).write_bytes(b"changed behind its back")
    with pytest.raises(IntegrityError, match="File corrupted or missing!"):
        ik.verify()


# -- what verification catches ----------------------------------------------------


def test_an_edited_seal_breaks_its_signature(ik: Archive, root: Path) -> None:
    _populate(ik)
    ik.seal()
    seals = _seal_lines(root)
    seals[0]["base"]["count"] = 2
    _write_seal_lines(root, seals)
    with pytest.raises(IntegrityError, match="Seal chain broken!"):
        Archive.open(root)


def test_a_seal_log_missing_its_first_seal_is_rejected(ik: Archive, root: Path) -> None:
    _populate(ik)
    ik.seal()
    ik.create_node("c")
    ik.seal()
    _write_seal_lines(root, _seal_lines(root)[1:])
    with pytest.raises(IntegrityError, match="Seal chain broken!"):
        Archive.open(root)


def test_a_seal_with_the_wrong_seq_is_rejected(ik: Archive, root: Path) -> None:
    _populate(ik)
    _forge(root, seq=2)
    with pytest.raises(IntegrityError, match="Seal chain broken!"):
        Archive.open(root)


def test_a_seal_pointing_to_a_wrong_head_is_rejected(ik: Archive, root: Path) -> None:
    _populate(ik)
    _forge(root, base=LogTip(head="sha256:" + "ab" * 32, count=3))
    with pytest.raises(IntegrityError, match="Seal does not match logs!"):
        Archive.open(root)


def test_a_rewritten_base_breaks_the_seal(ik: Archive, root: Path) -> None:
    for text in ("a", "b"):
        ik.create_node(text)
    ik.seal()
    shutil.rmtree(root / "events")
    forger = Builder(root, ALICE)
    for text in ("a", "B!"):
        forger.node(text)
    with pytest.raises(IntegrityError, match="Seal does not match logs!"):
        Archive.open(root)


def test_a_truncated_meta_log_breaks_the_seal(ik: Archive, root: Path) -> None:
    ik.create_node("a")
    ik.create_tag("t1", "d", kind="node")
    ik.create_tag("t2", "d", kind="node")
    ik.seal()
    (meta_file,) = (root / "meta" / "events").rglob("*ndjson")
    lines = meta_file.read_text("utf-8").splitlines(keepends=True)
    meta_file.write_text(lines[0], encoding="utf-8")
    with pytest.raises(IntegrityError, match="Seal does not match logs!"):
        Archive.open(root)


def test_a_seal_going_back_in_history_is_rejected(ik: Archive, root: Path) -> None:
    """D10: tip counts never decrease along the seal log."""
    ik.create_node("a")
    first_head = ik.head
    ik.create_node("b")
    ik.seal()
    _forge(root, base=LogTip(head=first_head, count=1))  # truthful, but older
    with pytest.raises(IntegrityError, match="Seal goes back in log history"):
        Archive.open(root)


@pytest.mark.parametrize("which", ["extra", "missing"])
def test_a_seal_with_a_wrong_blob_root_is_rejected(
    ik: Archive, root: Path, which: str
) -> None:
    _populate(ik)
    referenced = sorted(ik.index.store.referenced_blobs)
    stray = ik.index.store.blobs.put("not referenced by any event")
    wrong = [*referenced, stray] if which == "extra" else referenced[1:]
    _forge(root, root_hash=blob_root(wrong))
    with pytest.raises(IntegrityError, match="Blob set does not match seal!"):
        Archive.open(root)


def test_writes_after_a_seal_keep_the_archive_valid(ik: Archive, root: Path) -> None:
    """The issue option C fixes: new blobs after a seal must not break it."""
    _populate(ik)
    ik.seal()
    ik.create_node("new blob after the seal")
    assert len(Archive.open(root).seals()) == 1
    ik.seal()
    assert len(Archive.open(root).seals()) == 2


def test_a_stray_file_after_a_seal_only_warns(
    ik: Archive, root: Path, caplog: pytest.LogCaptureFixture
) -> None:
    _populate(ik)
    ik.seal()
    ik.index.store.blobs.put("slipped in after the seal")
    with caplog.at_level(logging.WARNING):
        reopened = Archive.open(root)
    assert len(reopened.seals()) == 1
    assert any("1 unreferenced blob" in r.getMessage() for r in caplog.records)


def test_an_unknown_seal_algorithm_is_rejected(ik: Archive, root: Path) -> None:
    _populate(ik)
    ik.seal()
    seals = _seal_lines(root)
    seals[0]["sig_alg"] = "ed448"
    _write_seal_lines(root, seals)
    with pytest.raises(IntegrityError, match="Unsupported algorithm"):
        Archive.open(root)


def test_seals_of_the_base_need_the_meta_log_too(ik: Archive, root: Path) -> None:
    """A seal commits to both logs: ship ``seals/`` only with ``meta/``."""
    _populate(ik)
    ik.seal()
    shutil.rmtree(root / "meta")
    with pytest.raises(IntegrityError, match="Seal does not match logs!"):
        Archive.open(root)
    shutil.rmtree(root / "seals")
    assert Archive.open(root).head == ik.head


# -- D11b: read-time warnings ---------------------------------------------------


def test_a_seal_of_an_empty_archive_only_warns_on_read(
    root: Path, caplog: pytest.LogCaptureFixture
) -> None:
    _forge(root)
    with caplog.at_level(logging.WARNING):
        reopened = Archive.open(root)
    assert len(reopened.seals()) == 1
    assert any("seals an empty archive" in r.getMessage() for r in caplog.records)


def test_a_repeated_seal_only_warns_on_read(
    ik: Archive, root: Path, caplog: pytest.LogCaptureFixture
) -> None:
    _populate(ik)
    ik.seal()
    _forge(root, BOB)
    with caplog.at_level(logging.WARNING):
        reopened = Archive.open(root)
    assert len(reopened.seals()) == 2
    assert any("Seal 2 repeats seal 1" in r.getMessage() for r in caplog.records)


# -- shipped seal vector --------------------------------------------------------


def test_shipped_seal_vector_is_reproduced() -> None:
    raw = files("indiek").joinpath("spec", "test_vectors.json").read_text("utf-8")
    document = json.loads(raw)
    (vector,) = document["seal_vectors"]
    events = {v["name"]: v for v in document["vectors"]}
    author = Author.from_seed_hex(vector["seed_hex"])
    unsigned = vector["seal_unsigned"]
    assert author.public_key_hex == vector["public_key_hex"] == unsigned["key"]
    assert canonical_bytes(unsigned).hex() == vector["signing_bytes_hex"]
    assert sign_object(unsigned, author, "sig") == vector["sig"]
    signed = {**unsigned, "sig": vector["sig"]}
    assert signed == vector["seal"]
    assert verify_object(signed, author.public_key_hex, "sig")
    assert digest(canonical_bytes(signed)) == vector["seal_hash"]
    # the seal commits to the shipped event vectors
    heads = {v["event_hash"] for v in events.values()}
    assert {unsigned["base"]["head"], unsigned["meta"]["head"]} <= heads
