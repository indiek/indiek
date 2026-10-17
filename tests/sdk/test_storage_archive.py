"""Unit tests for ``indiek.core.storage`` and ``indiek.core.archive``."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from indiek.core.archive import ArchiveStore, ChainState, verify_chain
from indiek.core.author import Author
from indiek.core.errors import IntegrityError
from indiek.core.models import EventHeader, EventModel, MediaType, Node
from indiek.core.signing import sign_event
from indiek.core.storage import BlobStore, EventLog

AUTHOR = Author.from_seed_hex("33" * 32)  # public test vector, not a secret
DAY1 = datetime(2026, 1, 1, tzinfo=UTC)
DAY2 = datetime(2026, 1, 2, tzinfo=UTC)


def _canonical_hex(event: dict[str, Any]) -> str:
    raw = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _append_node(
    log: EventLog,
    blobs: BlobStore,
    text: str,
    prev_hash: str | None,
    when: datetime = DAY1,
) -> dict[str, Any]:
    digest = blobs.put(text)
    event = EventModel(
        header=EventHeader(
            prev_hash=prev_hash, author=AUTHOR.public_key_hex, timestamp=when
        ),
        body=Node(blob_hash=digest, media_type=MediaType.TEXT_PLAIN, title=None),
    )
    event.signature = sign_event(event, AUTHOR)
    log.append(event)
    return json.loads(event.model_dump_json())


def _rewrite(log: EventLog, index: int, mutate: Any) -> None:
    """Apply ``mutate`` to the ``index``-th event of a single-file log."""
    (path,) = log.files()
    events = [json.loads(line) for line in path.read_text("utf-8").splitlines()]
    mutate(events[index])
    path.write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")


@pytest.fixture
def root(tmp_path: Path) -> Path:
    return tmp_path / "archive"


@pytest.fixture
def blobs(root: Path) -> BlobStore:
    return BlobStore(root)


@pytest.fixture
def log(root: Path) -> EventLog:
    return EventLog(root / "events")


# --- BlobStore -------------------------------------------------------------


def test_put_text_stores_utf8_under_a_sharded_path(
    blobs: BlobStore, root: Path
) -> None:
    digest = blobs.put("Gödel")
    assert digest == hashlib.sha256("Gödel".encode("utf-8")).hexdigest()
    path = root / "blobs" / "sha256" / digest[:2] / digest[2:4] / digest
    assert blobs.path_for(digest) == path
    assert path.read_bytes() == "Gödel".encode("utf-8")


def test_put_bytes_and_get_accept_prefixed_hashes(blobs: BlobStore) -> None:
    digest = blobs.put(b"\x89PNG")
    assert blobs.get(f"sha256:{digest}") == blobs.get(digest) == b"\x89PNG"


def test_identical_content_is_deduplicated(blobs: BlobStore) -> None:
    assert blobs.put("same") == blobs.put(b"same")
    assert len(blobs.iter_hashes()) == 1


def test_get_text_decodes_utf8(blobs: BlobStore) -> None:
    assert blobs.get_text("sha256:" + blobs.put("é")) == "é"


def test_verify_detects_tampered_and_missing_blobs(blobs: BlobStore) -> None:
    digest = blobs.put("body")
    assert blobs.verify(f"sha256:{digest}")
    blobs.path_for(digest).write_bytes(b"tampered")
    assert not blobs.verify(digest)
    assert not blobs.verify("0" * 64)


def test_iter_hashes_is_sorted(blobs: BlobStore) -> None:
    digests = [blobs.put(text) for text in ("c", "a", "b")]
    assert blobs.iter_hashes() == sorted(digests)


def test_empty_store_has_no_hashes(blobs: BlobStore) -> None:
    assert blobs.iter_hashes() == []


# --- EventLog --------------------------------------------------------------


def test_empty_log_iterates_nothing(log: EventLog) -> None:
    assert list(log) == []
    assert log.files() == []


def test_log_is_date_sharded_and_read_in_order(
    log: EventLog, blobs: BlobStore, root: Path
) -> None:
    first = _append_node(log, blobs, "one", None, DAY1)
    second = _append_node(log, blobs, "two", _canonical_hex(first), DAY2)
    assert log.files() == [
        root / "events/2026/01/01/events.ndjson",
        root / "events/2026/01/02/events.ndjson",
    ]
    assert list(log) == [first, second]


# --- verify_chain / ArchiveStore -----------------------------------------


def test_empty_chain(log: EventLog, blobs: BlobStore) -> None:
    assert verify_chain(log, blobs) == ChainState(head=None, count=0)


def test_valid_chain_head_is_hash_of_last_event(
    log: EventLog, blobs: BlobStore
) -> None:
    first = _append_node(log, blobs, "one", None)
    second = _append_node(log, blobs, "two", _canonical_hex(first))
    assert verify_chain(log, blobs) == ChainState(head=_canonical_hex(second), count=2)


def test_broken_chain(log: EventLog, blobs: BlobStore) -> None:
    first = _append_node(log, blobs, "one", None)
    _append_node(log, blobs, "two", _canonical_hex(first))
    _rewrite(log, 1, lambda e: e["header"].update(prev_hash="0" * 64))
    with pytest.raises(IntegrityError, match="Chain broken!"):
        verify_chain(log, blobs)


def test_tampered_body(log: EventLog, blobs: BlobStore) -> None:
    _append_node(log, blobs, "one", None)
    _rewrite(log, 0, lambda e: e["body"].update(title="forged"))
    with pytest.raises(IntegrityError, match="Data tampered or bad author!"):
        verify_chain(log, blobs)


def test_corrupted_blob(log: EventLog, blobs: BlobStore) -> None:
    event = _append_node(log, blobs, "one", None)
    blobs.path_for(event["body"]["blob_hash"]).write_bytes(b"x")
    with pytest.raises(IntegrityError, match="File corrupted or missing!"):
        verify_chain(log, blobs)


def test_missing_blob(log: EventLog, blobs: BlobStore) -> None:
    event = _append_node(log, blobs, "one", None)
    blobs.path_for(event["body"]["blob_hash"]).unlink()
    with pytest.raises(IntegrityError, match="File corrupted or missing!"):
        verify_chain(log, blobs)


def test_archive_store_open_verifies_both_logs(
    root: Path, log: EventLog, blobs: BlobStore
) -> None:
    event = _append_node(log, blobs, "one", None)
    store = ArchiveStore.open(root)
    assert (store.base_head, store.base_count) == (_canonical_hex(event), 1)
    assert (store.meta_head, store.meta_count) == (None, 0)
    assert store.meta_log.path == root / "meta" / "events"


def test_archive_store_open_raises_on_corruption(
    root: Path, log: EventLog, blobs: BlobStore
) -> None:
    _append_node(log, blobs, "one", None)
    _rewrite(log, 0, lambda e: e.update(signature="00" * 64))
    with pytest.raises(IntegrityError):
        ArchiveStore.open(root)
