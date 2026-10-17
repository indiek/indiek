"""Golden-archive characterisation test (CLIPYPI:SDK-REORG-LAYOUT).

Builds one fixed scenario with deterministic UUIDv7s, timestamps and signing
seed, then pins the base/meta head hashes and the blob set.  Any refactor that
changes a single byte of the archive output makes this test fail.  The head
constants were re-recorded for format 3.0 (CLIPYPI:FORMAT3-CANONICAL, 0.12.0;
the blob set is unchanged since 0.10.0).  When modules move, update only the
patch targets in ``_freeze``; change the constants only with a format change.

The seed below is a public test vector, not a secret.
"""

from __future__ import annotations

import hashlib
import json
import random
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

import pytest

import indiek.core.models as models_mod

GOLDEN_SEED_HEX = "11" * 32
START = datetime(2026, 1, 1, tzinfo=UTC)

EXPECTED_BASE_HEAD = "ae0519d55b7e613e97321ca4a277600e704f9b86221e399f3a1f6cc9dc556191"
EXPECTED_META_HEAD = "e1430fac790263c67fe11a6870a66046ca8875ac497130c36ec41c9261d721dd"
EXPECTED_BLOBS: list[str] = [
    "71a0b54b349d9f8a95d6bb621386c3cb939b0a711dbf4e746e3031c38b4104f5",
    "a089ebb18adefad6b93195cb15c2e4db2443d54e8d468117870538573f4d630c",
    "a4262e1c9bcbc1721eb3fe13558154460a2b2a2d307daa32532478526ce6ccb1",
    "d6d2c3442fa0541a0d1ad29dbcb149d2f3e1c9acde0c01493806a94174659637",
    "fff8bbdd94378cdbd956877c513032bc1658734c4a957a5baa557b8029fa463d",
]


def _freeze(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make ``uuid.uuid7`` and the event-header timestamp deterministic."""
    clock = {"ns": int(START.timestamp() * 1e9)}

    def time_ns() -> int:
        clock["ns"] += 1_000_000  # +1 ms per UUID
        return clock["ns"]

    rng = random.Random(0)
    monkeypatch.setattr(uuid, "time", SimpleNamespace(time_ns=time_ns))
    monkeypatch.setattr(uuid, "os", SimpleNamespace(urandom=rng.randbytes))
    monkeypatch.setattr(uuid, "_last_timestamp_v7", None)
    monkeypatch.setattr(uuid, "_last_counter_v7", None)

    ticks = {"n": 0}

    class _FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz: Any = None) -> datetime:  # type: ignore[override]
            ticks["n"] += 1
            return START + timedelta(seconds=ticks["n"])

    monkeypatch.setattr(models_mod, "dt", _FrozenDatetime)


def _head_hash(log_root: Path) -> str:
    """Canonical (format 3.0) hash of the last event under ``log_root/events``."""
    paths = sorted(str(p) for p in (log_root / "events").rglob("*ndjson"))
    last_line = Path(paths[-1]).read_text(encoding="utf-8").splitlines()[-1]
    event = json.loads(last_line)
    raw = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def test_golden_archive_is_byte_stable(
    run_cli: Callable[..., None],
    archive_root: Path,
    blob_paths: Callable[[], list[Path]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _freeze(monkeypatch)

    def ik(*argv: str) -> None:
        run_cli(*argv, seed_hex=GOLDEN_SEED_HEX)

    ik("create_node", "--content", "Gödel's incompleteness theorem")  # e1
    ik("create_node", "--content", "Peano arithmetic", "--title", "PA")  # e2
    ik(
        "create_edge",
        "--source-node",
        "e1",
        "--target-node",
        "e2",
        "--content",
        "about",
    )  # e3
    ik("supersede_node", "--node-id", "e1", "--content", "Gödel's *first* theorem")
    ik("supersede_edge", "--edge-id", "e3", "--content", "is about")
    ik(
        "create_node_tag", "--name", "theorem", "--description", "A proven statement"
    )  # m1
    ik("set_tag", "--tag", "m1", "--id", "e1")  # m2 representation, m3 meta edge

    base_head = _head_hash(archive_root)
    meta_head = _head_hash(archive_root / "meta")
    blobs = sorted(path.name for path in blob_paths())
    print(f"\nEXPECTED_BASE_HEAD = {base_head!r}")
    print(f"EXPECTED_META_HEAD = {meta_head!r}")
    print(f"EXPECTED_BLOBS = {blobs!r}")

    assert base_head == EXPECTED_BASE_HEAD
    assert meta_head == EXPECTED_META_HEAD
    assert blobs == EXPECTED_BLOBS
