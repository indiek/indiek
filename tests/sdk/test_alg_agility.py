"""Algorithm agility and transcription events (CLIPYPI:FORMAT3-ALG-AGILITY).

Owner decisions 2026-10-17:

* D1: ``header.hash_alg`` / ``header.sig_alg`` name the algorithms of an
  event; its ``signature`` prefix and its ``prev_hash`` prefix MUST equal them.
* D2: a transcription's ``verified_head`` / ``verified_count`` must match the
  earlier events of the log it sits in.
* D3: heads are prefixed digests (``sha256:<hex>``).
* D4 (option B): transcriptions may sit in the base or the meta log; each one
  attests only its own log.
* D5: transcribing an empty log is refused.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

import pytest
from _builders import Builder

from indiek import Archive, ArchiveRuleError, Author, AuthorshipError, IntegrityError
from indiek.core.canonical import (
    canonical_bytes,
    event_hash,
    parse_digest,
    parse_signature,
)
from indiek.core.models import Transcription
from indiek.core.signing import sign_event, verify_event

AUTHOR = Author.from_seed_hex("cc" * 32)  # public test vector, not a secret
OTHER = Author.from_seed_hex("dd" * 32)
HEX64 = "ab" * 32
HEX128 = "cd" * 64


@pytest.fixture
def root(tmp_path: Path) -> Path:
    return tmp_path / "archive"


@pytest.fixture
def ik(root: Path) -> Archive:
    return Archive.open(root, author=AUTHOR)


def _log_file(root: Path, network: str) -> Path:
    log_root = root / "events" if network == "base" else root / "meta" / "events"
    (path,) = log_root.rglob("*ndjson")
    return path


def _resign_last(
    root: Path, network: str, mutate: Callable[[dict[str, Any]], None]
) -> None:
    """Mutate the last event of a log, re-sign it with AUTHOR, rewrite the file."""
    path = _log_file(root, network)
    events = [json.loads(line) for line in path.read_text("utf-8").splitlines()]
    last = events[-1]
    mutate(last)
    last["signature"] = sign_event(last, AUTHOR)
    path.write_text(
        "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in events),
        encoding="utf-8",
    )


# -- parse_digest / parse_signature -----------------------------------------------


def test_parse_digest_splits_algorithm_and_hex() -> None:
    assert parse_digest(f"sha256:{HEX64}") == ("sha256", HEX64)


@pytest.mark.parametrize(
    "value",
    [HEX64, f"sha3-256:{HEX64}", "sha256:abcd", f"sha256:{HEX64.upper()}", ""],
    ids=["bare-hex", "unknown-alg", "too-short", "uppercase", "empty"],
)
def test_parse_digest_rejects_malformed_values(value: str) -> None:
    with pytest.raises(IntegrityError):
        parse_digest(value)


def test_parse_signature_splits_algorithm_and_bytes() -> None:
    assert parse_signature(f"ed25519:{HEX128}") == ("ed25519", bytes.fromhex(HEX128))


@pytest.mark.parametrize(
    "value",
    [HEX128, f"ed448:{HEX128}", "ed25519:abcd", f"ed25519:{'zz' * 64}"],
    ids=["bare-hex", "unknown-alg", "too-short", "non-hex"],
)
def test_parse_signature_rejects_malformed_values(value: str) -> None:
    with pytest.raises(IntegrityError):
        parse_signature(value)


def test_event_hash_and_signature_are_prefixed() -> None:
    event = {
        "header": {
            "version": "3.0",
            "hash_alg": "sha256",
            "sig_alg": "ed25519",
            "prev_hash": None,
            "timestamp": "2026-10-17T12:00:00Z",
            "author": AUTHOR.public_key_hex,
        },
        "body": {"a": "Gödel"},
    }
    signature = sign_event(event, AUTHOR)
    expected = AUTHOR.sign(canonical_bytes(event)).hex()
    assert signature == f"ed25519:{expected}"
    signed = {**event, "signature": signature}
    assert verify_event(signed)
    digest = hashlib.sha256(canonical_bytes(signed)).hexdigest()
    assert event_hash(signed) == f"sha256:{digest}"


# -- what the SDK writes (D1, D3) --------------------------------------------------


def test_written_events_declare_and_use_prefixed_algorithms(ik: Archive) -> None:
    ik.create_node("one")
    ik.create_node("two")
    ik.create_tag("t", "d", kind="node")
    first, second = list(ik.events())
    (meta,) = list(ik.events("meta"))
    for event in (first, second, meta):
        assert event["header"]["hash_alg"] == "sha256"
        assert event["header"]["sig_alg"] == "ed25519"
        assert event["signature"].startswith("ed25519:")
    assert first["header"]["prev_hash"] is None
    assert second["header"]["prev_hash"] == event_hash(first)
    assert second["header"]["prev_hash"].startswith("sha256:")
    assert ik.head == event_hash(second)
    assert ik.meta_head == event_hash(meta)


# -- D1 rejections ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "value"),
    [("hash_alg", "sha3-256"), ("sig_alg", "ed448"), ("hash_alg", None)],
    ids=["unknown-hash-alg", "unknown-sig-alg", "missing-hash-alg"],
)
def test_unsupported_header_algorithm_is_rejected(
    ik: Archive, root: Path, field: str, value: str | None
) -> None:
    ik.create_node("one")

    def mutate(event: dict[str, Any]) -> None:
        if value is None:
            del event["header"][field]
        else:
            event["header"][field] = value

    _resign_last(root, "base", mutate)
    with pytest.raises(IntegrityError, match="Unsupported algorithm"):
        Archive.open(root)


def test_signature_prefix_must_match_sig_alg(ik: Archive, root: Path) -> None:
    ik.create_node("one")
    path = _log_file(root, "base")
    event = json.loads(path.read_text("utf-8"))
    event["signature"] = "ed448:" + event["signature"].removeprefix("ed25519:")
    path.write_text(json.dumps(event, ensure_ascii=False) + "\n", encoding="utf-8")
    with pytest.raises(IntegrityError, match="Algorithm mismatch"):
        Archive.open(root)


def test_prev_hash_prefix_must_match_hash_alg(ik: Archive, root: Path) -> None:
    ik.create_node("one")
    ik.create_node("two")

    def mutate(event: dict[str, Any]) -> None:
        _, digest = parse_digest(event["header"]["prev_hash"])
        event["header"]["prev_hash"] = f"sha512:{digest}"

    _resign_last(root, "base", mutate)
    with pytest.raises(IntegrityError, match="Algorithm mismatch"):
        Archive.open(root)


@pytest.mark.parametrize("field", ["signature", "prev_hash"])
def test_a_bare_hex_value_is_an_algorithm_mismatch(
    ik: Archive, root: Path, field: str
) -> None:
    """Owner refinement of D1: a missing prefix is a mismatch too."""
    ik.create_node("one")
    ik.create_node("two")
    path = _log_file(root, "base")
    events = [json.loads(line) for line in path.read_text("utf-8").splitlines()]
    last = events[-1]
    if field == "signature":
        last["signature"] = last["signature"].removeprefix("ed25519:")
    else:
        last["header"]["prev_hash"] = parse_digest(last["header"]["prev_hash"])[1]
        last["signature"] = sign_event(last, AUTHOR)
    path.write_text(
        "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in events),
        encoding="utf-8",
    )
    with pytest.raises(IntegrityError, match="Algorithm mismatch"):
        Archive.open(root)


# -- transcription events (D2, D4, D5) ------------------------------------------


def test_transcribe_base_attests_the_current_head(ik: Archive) -> None:
    ik.create_node("one")
    ik.create_node("two")
    head_before = ik.head
    returned = ik.transcribe(note="re-verified")
    assert returned == ik.head

    event = list(ik.events())[-1]
    body = event["body"]
    assert (body["body_type"], body["event_type"]) == ("transcription", "transcription")
    assert body["verified_head"] == head_before
    assert body["verified_count"] == 2
    assert (body["verified_hash_alg"], body["verified_sig_alg"]) == (
        "sha256",
        "ed25519",
    )
    assert body["note"] == "re-verified"
    verified_at = datetime.fromisoformat(body["verified_at"])
    assert verified_at.tzinfo is not None and verified_at <= datetime.now(UTC)

    (record,) = ik.index.transcriptions["base"]
    assert (record.author, record.position) == (AUTHOR.public_key_hex, 3)
    assert record.body == body
    assert ik.index.transcriptions["meta"] == []


def test_transcription_allocates_no_alias_and_changes_no_projection(
    ik: Archive,
) -> None:
    ik.create_node("one")
    ik.create_node("two")
    items_before = {k: (v.alias, v.body) for k, v in ik.index.items.items()}
    ik.transcribe()
    assert {k: (v.alias, v.body) for k, v in ik.index.items.items()} == items_before
    node = ik.create_node("three")
    assert ik.index.alias_of(node) == "e3"


def test_transcribe_meta_attests_only_the_meta_log(ik: Archive) -> None:
    ik.create_node("base node")
    ik.create_tag("t1", "d", kind="node")
    base_head, meta_head = ik.head, ik.meta_head
    assert ik.transcribe(network="meta") == ik.meta_head
    assert ik.head == base_head  # the base log is untouched

    body = list(ik.events("meta"))[-1]["body"]
    assert (body["verified_head"], body["verified_count"]) == (meta_head, 1)
    assert [r.position for r in ik.index.transcriptions["meta"]] == [2]
    assert ik.index.transcriptions["base"] == []
    tag = ik.create_tag("t2", "d", kind="node")
    assert ik.index.alias_of(tag) == "m2"


def test_a_transcribed_archive_reopens_and_keeps_its_records(
    ik: Archive, root: Path
) -> None:
    ik.create_node("one")
    ik.transcribe()
    ik.create_node("two")
    ik.transcribe()
    reopened = Archive.open(root)
    assert [
        r.body["verified_count"] for r in reopened.index.transcriptions["base"]
    ] == [
        1,
        3,
    ]


def test_another_author_may_transcribe(ik: Archive, root: Path) -> None:
    ik.create_node("one")
    other = Archive.open(root, author=OTHER)
    other.transcribe()
    (record,) = other.index.transcriptions["base"]
    assert record.author == OTHER.public_key_hex


def test_transcribe_needs_an_author(ik: Archive, root: Path) -> None:
    ik.create_node("one")
    with pytest.raises(AuthorshipError, match="An author is required"):
        Archive.open(root).transcribe()


@pytest.mark.parametrize("network", ["base", "meta"])
def test_transcribing_an_empty_log_is_refused(ik: Archive, network: str) -> None:
    with pytest.raises(ArchiveRuleError, match=f"the {network} log is empty"):
        ik.transcribe(network=network)  # type: ignore[arg-type]
    assert list(ik.events(network)) == []  # type: ignore[arg-type]


def test_transcribe_rejects_an_unknown_network(ik: Archive) -> None:
    ik.create_node("one")
    with pytest.raises(ValueError, match="network"):
        ik.transcribe(network="other")  # type: ignore[arg-type]


def _forged(verified_head: str, verified_count: int) -> Transcription:
    return Transcription(
        verified_head=verified_head,
        verified_count=verified_count,
        verified_hash_alg="sha256",
        verified_sig_alg="ed25519",
        verified_at=datetime(2026, 10, 17, tzinfo=UTC),
    )


@pytest.mark.parametrize("network", ["base", "meta"])
def test_a_transcription_with_a_wrong_head_is_rejected(
    root: Path, network: str
) -> None:
    build = Builder(root, AUTHOR)
    build.node("one")
    build.tag("t")
    append = build.raw_base if network == "base" else build.raw_meta
    append(_forged(f"sha256:{HEX64}", 1))  # type: ignore[arg-type]
    with pytest.raises(IntegrityError, match="Transcription does not match chain"):
        Archive.open(root)


def test_a_transcription_cannot_attest_itself_or_the_future(root: Path) -> None:
    build = Builder(root, AUTHOR)
    build.node("one")
    build.node("two")
    build.raw_base(_forged(f"sha256:{HEX64}", 3))  # its own position
    with pytest.raises(IntegrityError, match="Transcription does not match chain"):
        Archive.open(root)


def test_a_correct_forged_style_transcription_verifies(root: Path) -> None:
    build = Builder(root, AUTHOR)
    build.node("one")
    head = Archive.open(root).head
    assert head is not None
    build.raw_base(_forged(head, 1))
    assert len(Archive.open(root).index.transcriptions["base"]) == 1


# -- MANIFEST algorithms ---------------------------------------------------------


def test_manifest_lists_the_algorithms_used(ik: Archive) -> None:
    ik.create_node("one")
    ik.create_tag("t", "d", kind="node")
    data = json.loads(ik.write_manifest().read_text(encoding="utf-8"))
    assert data["algorithms"] == {"hash": ["sha256"], "signature": ["ed25519"]}
    assert data["authors"] == [
        {"public_key": AUTHOR.public_key_hex, "algorithm": "Ed25519"}
    ]


def test_manifest_of_an_empty_archive_lists_no_algorithms(root: Path) -> None:
    data = json.loads(Archive.open(root).write_manifest().read_text(encoding="utf-8"))
    assert data["algorithms"] == {"hash": [], "signature": []}
