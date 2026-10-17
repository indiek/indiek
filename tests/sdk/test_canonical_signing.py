"""Unit tests for ``indiek.core.canonical`` and ``indiek.core.signing`` (format 3.0).

The reference implementation of the 3.0 rule is spelled out inline (stdlib +
PyNaCl only) so these tests pin the rule independently of the SDK:

* canonical bytes = ``json.dumps(obj, sort_keys=True, separators=(",", ":"),
  ensure_ascii=False)`` encoded as UTF-8;
* signature = Ed25519 over the canonical bytes of the whole event minus its
  ``signature`` field (no pre-hash);
* event hash = ``sha256:`` + SHA-256 hex of the canonical bytes of the whole
  event; signatures are stored as ``ed25519:<hex>`` (CLIPYPI:FORMAT3-ALG-AGILITY).
"""

from __future__ import annotations

import copy
import hashlib
import json
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel

from indiek import Archive, Author, IntegrityError
from indiek.core.archive import verify_chain
from indiek.core.canonical import canonical_bytes, event_hash
from indiek.core.signing import sign_event, verify_event
from indiek.core.storage import BlobStore, EventLog

BODY: dict[str, Any] = {"b": [1, 2], "a": "Gödel", "c": {"y": None, "x": True}}
SEED_HEX = "22" * 32  # public test vector, not a secret


class _Sample(BaseModel):
    name: str
    count: int


def _reference_bytes(obj: dict[str, Any]) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _unsigned_event(author: Author, prev_hash: str | None = None) -> dict[str, Any]:
    return {
        "header": {
            "version": "3.0",
            "hash_alg": "sha256",
            "sig_alg": "ed25519",
            "prev_hash": prev_hash,
            "timestamp": "2026-10-17T12:00:00Z",
            "author": author.public_key_hex,
        },
        "body": copy.deepcopy(BODY),
    }


def _signed_event(author: Author, prev_hash: str | None = None) -> dict[str, Any]:
    event = _unsigned_event(author, prev_hash)
    return {**event, "signature": sign_event(event, author)}


# -- canonical bytes and hashes ---------------------------------------------


def test_canonical_bytes_follow_the_3_0_rule() -> None:
    assert canonical_bytes(BODY) == _reference_bytes(BODY)
    # compact separators and raw UTF-8, no ASCII escaping
    assert '"a":"Gödel"'.encode() in canonical_bytes(BODY)
    assert b", " not in canonical_bytes(BODY) and b": " not in canonical_bytes(BODY)


def test_canonical_bytes_are_key_order_independent() -> None:
    reordered = {"c": {"x": True, "y": None}, "a": "Gödel", "b": [1, 2]}
    assert canonical_bytes(BODY) == canonical_bytes(reordered)


def test_model_and_its_json_dump_are_canonically_equal() -> None:
    model = _Sample(name="n", count=3)
    assert canonical_bytes(model) == canonical_bytes(model.model_dump(mode="json"))


def test_event_hash_covers_the_whole_event_including_signature() -> None:
    event = _signed_event(Author.from_seed_hex(SEED_HEX))
    expected = hashlib.sha256(_reference_bytes(event)).hexdigest()
    assert event_hash(event) == f"sha256:{expected}"
    assert event_hash(event) != event_hash({**event, "signature": "00" * 64})


# -- signing ------------------------------------------------------------------


def test_sign_event_matches_reference_signature() -> None:
    author = Author.from_seed_hex(SEED_HEX)
    event = _unsigned_event(author)
    signature = author.signing_key.sign(_reference_bytes(event)).signature.hex()
    expected = f"ed25519:{signature}"
    assert sign_event(event, author) == expected
    # a present ``signature`` field (e.g. ``None`` on a fresh model) is ignored
    assert sign_event({**event, "signature": None}, author) == expected


def test_sign_then_verify_round_trip() -> None:
    event = _signed_event(Author.from_seed_hex(SEED_HEX))
    signature = event["signature"]
    assert signature.startswith("ed25519:") and len(signature) == len("ed25519:") + 128
    assert signature == signature.lower()
    assert verify_event(event)


def test_verify_rejects_mutated_body() -> None:
    event = _signed_event(Author.from_seed_hex(SEED_HEX))
    event["body"]["a"] = "changed"
    assert not verify_event(event)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("timestamp", "2099-01-01T00:00:00Z"),
        ("prev_hash", "ab" * 32),
        ("version", "3.1"),
    ],
)
def test_verify_rejects_mutated_header(field: str, value: str) -> None:
    event = _signed_event(Author.from_seed_hex(SEED_HEX))
    event["header"][field] = value
    assert not verify_event(event)


def test_verify_rejects_another_authors_key() -> None:
    event = _signed_event(Author.from_seed_hex(SEED_HEX))
    event["header"]["author"] = Author.generate().public_key_hex
    assert not verify_event(event)


@pytest.mark.parametrize("signature", ["zz", "", "00" * 64, None])
def test_verify_rejects_malformed_or_wrong_signature(signature: str | None) -> None:
    event = _signed_event(Author.from_seed_hex(SEED_HEX))
    assert not verify_event({**event, "signature": signature})


def test_verify_rejects_malformed_public_key() -> None:
    event = _signed_event(Author.from_seed_hex(SEED_HEX))
    event["header"]["author"] = "not-hex"
    assert not verify_event(event)


# -- the replay attack that body-only signing allowed -------------------------


def test_replayed_old_supersede_under_a_new_header_fails_verification(
    tmp_path: Path,
) -> None:
    alice = Author.from_seed_hex(SEED_HEX)
    ik = Archive.open(tmp_path / "archive", author=alice)
    node = ik.create_node("draft")
    ik.supersede_node(node, "X is true")
    ik.supersede_node(node, "X is false, I was wrong")
    _, old_supersede, last = list(ik.events("base"))

    # Mallory re-chains Alice's old signed supersede onto the current head.
    replay = copy.deepcopy(old_supersede)
    replay["header"]["prev_hash"] = event_hash(last)
    replay["header"]["timestamp"] = "2026-12-31T00:00:00Z"
    log_file = ik.index.store.base_log.files()[-1]
    with open(log_file, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(replay, ensure_ascii=False) + "\n")

    with pytest.raises(IntegrityError, match="Data tampered or bad author!"):
        Archive.open(tmp_path / "archive")


# -- strict parsing of log lines ---------------------------------------------


def _write_log_line(root: Path, line: str) -> EventLog:
    day = root / "events" / "2026" / "10" / "17"
    day.mkdir(parents=True)
    (day / "events.ndjson").write_text(line + "\n", encoding="utf-8")
    return EventLog(root / "events")


@pytest.mark.parametrize(
    "line",
    ['{"a": 1, "a": 2}', '{"a": {"b": 1, "b": 1}}', '{"a": 1.5}', '{"a": [1e3]}'],
    ids=["duplicate-key", "nested-duplicate-key", "float", "exponent-float"],
)
def test_log_lines_with_duplicate_keys_or_floats_are_rejected(
    tmp_path: Path, line: str
) -> None:
    with pytest.raises(IntegrityError):
        list(_write_log_line(tmp_path, line))


@pytest.mark.parametrize("version", ["1.0", "2.0", "3.1"])
def test_events_of_another_format_version_are_rejected(
    tmp_path: Path, version: str
) -> None:
    author = Author.from_seed_hex(SEED_HEX)
    event = _unsigned_event(author)
    event["header"]["version"] = version
    event["signature"] = sign_event(event, author)  # validly signed, wrong version
    log = _write_log_line(tmp_path, json.dumps(event, ensure_ascii=False))
    with pytest.raises(IntegrityError, match="Unsupported format version"):
        verify_chain(log, BlobStore(tmp_path))


def test_a_valid_3_0_chain_verifies(tmp_path: Path) -> None:
    author = Author.from_seed_hex(SEED_HEX)
    first = _signed_event(author)
    second = _signed_event(author, prev_hash=event_hash(first))
    lines = "\n".join(json.dumps(e, ensure_ascii=False) for e in (first, second))
    state = verify_chain(_write_log_line(tmp_path, lines), BlobStore(tmp_path))
    assert (state.head, state.count) == (event_hash(second), 2)


@pytest.mark.parametrize("drop", [1, 2], ids=["first-event-deleted", "two-deleted"])
def test_a_log_missing_its_first_events_is_rejected(tmp_path: Path, drop: int) -> None:
    author = Author.from_seed_hex(SEED_HEX)
    chain = [_signed_event(author)]
    for _ in range(2):
        chain.append(_signed_event(author, prev_hash=event_hash(chain[-1])))
    lines = "\n".join(json.dumps(e, ensure_ascii=False) for e in chain[drop:])
    with pytest.raises(IntegrityError, match="Chain broken!"):
        verify_chain(_write_log_line(tmp_path, lines), BlobStore(tmp_path))


# -- shipped test vectors -----------------------------------------------------


def _test_vectors() -> list[dict[str, Any]]:
    raw = (
        files("indiek")
        .joinpath("spec", "test_vectors.json")
        .read_text(encoding="utf-8")
    )
    document = json.loads(raw)
    assert document["format_version"] == "3.0"
    assert document["vectors"]
    return document["vectors"]


def test_shipped_test_vectors_are_reproduced() -> None:
    for vector in _test_vectors():
        author = Author.from_seed_hex(vector["seed_hex"])
        unsigned = vector["event_unsigned"]
        assert author.public_key_hex == vector["public_key_hex"], vector["name"]
        assert canonical_bytes(unsigned).hex() == vector["signing_bytes_hex"], vector[
            "name"
        ]
        assert sign_event(unsigned, author) == vector["signature"], vector["name"]
        signed = {**unsigned, "signature": vector["signature"]}
        assert signed == vector["event"], vector["name"]
        assert verify_event(signed), vector["name"]
        assert event_hash(signed) == vector["event_hash"], vector["name"]
