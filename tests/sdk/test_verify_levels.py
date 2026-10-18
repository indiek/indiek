"""Verification levels, the local cache and trusted seals (CLIPYPI:VERIFY-LEVELS-CACHE).

Owner decisions 2026-10-17 (trust model): verification work may be skipped
only on the basis of (a) this machine's own cache, stored OUTSIDE the archive,
or (b) a seal hash the reader supplies (obtained through a separate route);
NEVER (c) on the basis of a seal merely found in the archive.  D13 levels
NONE / INCREMENTAL (default) / FULL; D14 the cache records verified chain
tips (checked by recomputing the chain) and blob (size, mtime_ns); D15 per-OS
cache dirs + ``IK_CACHE_DIR``; D16 blobs are verified on read.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from _builders import Builder

import indiek.core.archive as archive_mod
from indiek import (
    Archive,
    ArchiveRuleError,
    Author,
    IntegrityError,
    MediaType,
    VerificationLevel,
)
from indiek.core.archive import ArchiveStore
from indiek.core.cache import cache_path, default_cache_dir
from indiek.core.canonical import event_hash
from indiek.core.index import ArchiveIndex
from indiek.core.merkle import blob_root
from indiek.core.models import LogTip, SealModel
from indiek.core.signing import sign_object
from indiek.core.storage import BlobStore, SealLog
from indiek.ops.nodes import create_managed_node

ALICE = Author.from_seed_hex("a5" * 32)  # public test vectors, not secrets
MALLORY = Author.from_seed_hex("e4" * 32)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    return tmp_path / "archive"


@pytest.fixture
def signature_checks(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Count Ed25519 event-signature checks made while verifying logs."""
    calls: list[int] = []
    original = archive_mod.verify_event

    def counting(event: dict[str, Any]) -> bool:
        calls.append(1)
        return original(event)

    monkeypatch.setattr(archive_mod, "verify_event", counting)
    return calls


@pytest.fixture
def blob_rehashes(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record every blob re-hashed by ``BlobStore.verify``."""
    calls: list[str] = []
    original = BlobStore.verify

    def counting(self: BlobStore, blob_hash: str) -> bool:
        calls.append(blob_hash)
        return original(self, blob_hash)

    monkeypatch.setattr(BlobStore, "verify", counting)
    return calls


def _three_nodes(root: Path) -> Archive:
    ik = Archive.open(root, author=ALICE)
    for text in ("a", "b", "c"):
        ik.create_node(text)
    return ik


def _rewrite_base(root: Path, mutate: Callable[[list[dict[str, Any]]], None]) -> None:
    (path,) = (root / "events").rglob("*ndjson")
    events = [json.loads(line) for line in path.read_text("utf-8").splitlines()]
    mutate(events)
    path.write_text(
        "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in events), "utf-8"
    )


# -- D15: where the cache lives -------------------------------------------------------


@pytest.mark.parametrize(
    ("platform", "environ", "expected"),
    [
        ("darwin", {}, "HOME/Library/Caches/indiek"),
        ("linux", {}, "HOME/.cache/indiek"),
        ("linux", {"XDG_CACHE_HOME": "/xdg"}, "/xdg/indiek"),
        ("win32", {"LOCALAPPDATA": "/local"}, "/local/indiek/Cache"),
        ("win32", {}, "HOME/AppData/Local/indiek/Cache"),
        ("darwin", {"IK_CACHE_DIR": "/override"}, "/override"),
    ],
)
def test_default_cache_dir_follows_platform_conventions(
    platform: str, environ: dict[str, str], expected: str
) -> None:
    home = Path("/home/user")
    got = default_cache_dir(environ=environ, platform=platform, home=home)
    assert got == Path(expected.replace("HOME", str(home)))


def test_the_cache_lives_outside_the_archive(root: Path, ik_cache_dir: Path) -> None:
    _three_nodes(root)
    path = cache_path(ik_cache_dir, root)
    assert path.is_file() and ik_cache_dir in path.parents
    assert not any(p.name.startswith(".ik") for p in root.iterdir())
    data = json.loads(path.read_text("utf-8"))
    assert set(data) == {"format", "archive", "logs", "blobs"}
    assert data["logs"]["base"]["count"] == 3
    referenced = Archive.open(root).index.store.referenced_blobs
    assert set(data["blobs"]) == referenced  # digests and stats only, no content


def test_two_archives_get_two_cache_entries(tmp_path: Path, ik_cache_dir: Path) -> None:
    _three_nodes(tmp_path / "one")
    _three_nodes(tmp_path / "two")
    assert cache_path(ik_cache_dir, tmp_path / "one") != cache_path(
        ik_cache_dir, tmp_path / "two"
    )


# -- (a): the local cache --------------------------------------------------------------


def test_incremental_skips_what_this_machine_already_verified(
    root: Path, signature_checks: list[int], blob_rehashes: list[str]
) -> None:
    ik = _three_nodes(root)
    signature_checks.clear()
    blob_rehashes.clear()

    Archive.open(root)
    assert signature_checks == [] and blob_rehashes == []

    ik.create_node("d")  # its refresh verifies only the new event
    signature_checks.clear()
    Archive.open(root)
    assert signature_checks == []


def test_events_appended_elsewhere_are_fully_checked(
    root: Path, signature_checks: list[int]
) -> None:
    _three_nodes(root)
    # another writer that does not touch this machine's cache
    index = ArchiveIndex(ArchiveStore.open(root))
    create_managed_node(index, ALICE, "written elsewhere", MediaType.TEXT_PLAIN)
    signature_checks.clear()
    Archive.open(root)
    assert len(signature_checks) == 1


def test_full_ignores_the_cache(root: Path, signature_checks: list[int]) -> None:
    _three_nodes(root)
    signature_checks.clear()
    Archive.open(root, verify=VerificationLevel.FULL)
    assert len(signature_checks) == 3


def test_a_tampered_event_is_caught_despite_the_cache(root: Path) -> None:
    _three_nodes(root)
    _rewrite_base(root, lambda events: events[1]["body"].update(title="forged"))
    with pytest.raises(IntegrityError, match="Data tampered or bad author!"):
        Archive.open(root)


def test_a_stale_cache_falls_back_to_a_full_check(
    root: Path, ik_cache_dir: Path, signature_checks: list[int]
) -> None:
    _three_nodes(root)
    path = cache_path(ik_cache_dir, root)
    data = json.loads(path.read_text("utf-8"))
    data["logs"]["base"]["head"] = "sha256:" + "00" * 32
    path.write_text(json.dumps(data), "utf-8")
    signature_checks.clear()
    Archive.open(root)
    assert len(signature_checks) == 3


@pytest.mark.parametrize("content", ["not json", "[]", '{"logs": 3}'])
def test_a_corrupted_cache_is_ignored(
    root: Path, ik_cache_dir: Path, signature_checks: list[int], content: str
) -> None:
    _three_nodes(root)
    cache_path(ik_cache_dir, root).write_text(content, "utf-8")
    signature_checks.clear()
    Archive.open(root)
    assert len(signature_checks) == 3


def test_a_cache_planted_inside_the_archive_is_never_read(
    root: Path, signature_checks: list[int], ik_cache_dir: Path
) -> None:
    _three_nodes(root)
    planted = root / ".ik-cache"
    planted.mkdir()
    cache_path(ik_cache_dir, root).rename(planted / "state.json")
    signature_checks.clear()
    Archive.open(root)
    assert len(signature_checks) == 3


def test_a_changed_blob_file_is_rehashed_and_caught(
    root: Path, blob_rehashes: list[str]
) -> None:
    ik = _three_nodes(root)
    blob = ik.index.store.blobs.path_for(ik.index.get("e2").body["blob_hash"])
    blob.write_bytes(b"rotten bytes")
    with pytest.raises(IntegrityError, match="File corrupted or missing!"):
        Archive.open(root)


@pytest.mark.parametrize(
    "n_events",
    [1_000, pytest.param(10_000, marks=pytest.mark.slow)],  # slow: ~20 s
)
def test_a_large_archive_reopens_without_signature_checks(
    root: Path, signature_checks: list[int], n_events: int
) -> None:
    builder = Builder(root, ALICE)
    for i in range(n_events):
        builder.node(f"node {i}")
    Archive.open(root)  # first open: full work, fills the cache
    assert len(signature_checks) == n_events

    signature_checks.clear()
    Archive.open(root)
    assert signature_checks == []

    builder.node("one more")
    signature_checks.clear()
    Archive.open(root)
    assert len(signature_checks) == 1


# -- D16: blobs are verified on read ---------------------------------------------------


def test_bit_rot_hidden_from_the_cache_is_caught_on_read(root: Path) -> None:
    ik = _three_nodes(root)
    blob_hash = ik.index.get("e1").body["blob_hash"]
    path = ik.index.store.blobs.path_for(blob_hash)
    stat = path.stat()
    path.write_bytes(b"z")  # same size as "a"
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns))  # and same mtime

    reopened = Archive.open(root)  # the cache's blind spot
    with pytest.raises(IntegrityError, match="File corrupted or missing!"):
        reopened.index.store.blobs.get_text(blob_hash)
    with pytest.raises(IntegrityError, match="File corrupted or missing!"):
        Archive.open(root, verify="full")


def test_reading_a_missing_blob_is_an_integrity_error(root: Path) -> None:
    store = BlobStore(root)
    with pytest.raises(IntegrityError, match="File corrupted or missing!"):
        store.get("sha256:" + "ab" * 32)


# -- (b): a seal hash supplied by the reader ------------------------------------------


def test_a_trusted_seal_skips_the_signatures_it_covers(
    root: Path, ik_cache_dir: Path, signature_checks: list[int]
) -> None:
    ik = _three_nodes(root)
    sealed = ik.seal()
    ik.create_node("after the seal")
    cache_path(ik_cache_dir, root).unlink()  # a reader who never saw it before

    signature_checks.clear()
    opened = Archive.open(root, trusted_seal=sealed.hash)
    assert len(signature_checks) == 1  # only the event after the seal
    assert opened.head == ik.head


def test_a_trusted_seal_missing_from_the_log_is_rejected(root: Path) -> None:
    _three_nodes(root)
    with pytest.raises(IntegrityError, match="Expected seal not found in seal log"):
        Archive.open(root, trusted_seal="sha256:" + "00" * 32)


def test_a_trusted_seal_does_not_hide_a_tampered_prefix(root: Path) -> None:
    ik = _three_nodes(root)
    sealed = ik.seal()
    _rewrite_base(root, lambda events: events[0]["body"].update(title="forged"))
    with pytest.raises(IntegrityError):
        Archive.open(root, trusted_seal=sealed.hash)


# -- never (c): a seal found in the archive is checked, never trusted ------------------


def _mallory_forges_and_seals(root: Path) -> None:
    """Edit Alice's event #2 (keeping her as author), re-chain the rest, and
    seal the forged state with Mallory's own, valid key."""

    def forge(events: list[dict[str, Any]]) -> None:
        events[1]["body"]["title"] = "Alice now says X is false"
        for previous, event in zip(events, events[1:]):
            event["header"]["prev_hash"] = event_hash(previous)

    _rewrite_base(root, forge)
    store = Archive.open(root, verify="none").index.store
    model = SealModel(
        seq=1,
        prev_seal_hash=None,
        base=LogTip(head=store.base.head, count=store.base.count),
        meta=LogTip(head=None, count=0),
        blob_root=blob_root(store.referenced_blobs),
        key=MALLORY.public_key_hex,
    )
    model.sig = sign_object(model, MALLORY, "sig")
    SealLog(root / "seals").append(model)


@pytest.mark.parametrize("cache", ["fresh reader", "reader with a cache"])
def test_a_seal_found_in_the_archive_is_never_trusted(
    root: Path, ik_cache_dir: Path, cache: str
) -> None:
    _three_nodes(root)
    if cache == "fresh reader":
        cache_path(ik_cache_dir, root).unlink()
    _mallory_forges_and_seals(root)
    with pytest.raises(IntegrityError, match="Data tampered or bad author!"):
        Archive.open(root)


# -- D13: NONE -----------------------------------------------------------------------


def test_none_parses_a_damaged_archive_but_refuses_writes(
    root: Path, ik_cache_dir: Path
) -> None:
    _three_nodes(root)
    cache = cache_path(ik_cache_dir, root)
    before = cache.read_bytes()
    _rewrite_base(root, lambda events: events[1]["body"].update(title="forged"))

    ik = Archive.open(root, author=ALICE, verify=VerificationLevel.NONE)
    assert ik.index.get("e2").body["title"] == "forged"
    assert ik.verification is VerificationLevel.NONE
    assert cache.read_bytes() == before  # NONE neither reads nor writes the cache
    with pytest.raises(ArchiveRuleError, match="verify='none'"):
        ik.create_node("x")


def test_operations_that_need_full_verification_force_it(
    root: Path, signature_checks: list[int], tmp_path: Path
) -> None:
    ik = _three_nodes(root)
    for operation in (
        ik.verify,
        lambda: ik.export_graphml(tmp_path / "g.graphml"),
        ik.write_manifest,
        lambda: ik.ingest(),
    ):
        signature_checks.clear()
        operation()
        assert len(signature_checks) == 3, operation
    assert ik.verification is VerificationLevel.INCREMENTAL


def test_seal_forces_full_verification(root: Path, signature_checks: list[int]) -> None:
    ik = _three_nodes(root)
    signature_checks.clear()
    ik.seal()
    assert len(signature_checks) >= 3


def test_levels_accept_strings(root: Path) -> None:
    _three_nodes(root)
    assert Archive.open(root, verify="full").verification is VerificationLevel.FULL
    with pytest.raises(ValueError):
        Archive.open(root, verify="head_only")


# -- fsck ------------------------------------------------------------------------------


def test_fsck_reports_the_whole_archive(root: Path) -> None:
    ik = _three_nodes(root)
    ik.create_tag("t", "d", kind="edge")
    ik.create_edge("e1", "e2", "ab")
    ik.seal()
    ik.transcribe()
    with pytest.raises(ArchiveRuleError):
        ik.set_tag("m1", "e1")  # leaves an untagged node representation (m2)
    stray = ik.index.store.blobs.put("stray")

    report = ik.fsck()
    assert (report.base_count, report.meta_count) == (5, 2)
    assert (report.base_head, report.meta_head) == (ik.head, ik.meta_head)
    assert report.seal_count == 1 and report.latest_seal == ik.seals()[-1]
    assert report.transcriptions == {"base": 1, "meta": 0}
    assert report.referenced_blobs == 4
    assert [p.name for p in report.unreferenced_blobs] == [stray]
    assert report.untagged_representations == 1
