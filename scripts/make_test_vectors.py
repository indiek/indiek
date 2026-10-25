"""Regenerate ``src/indiek/spec/test_vectors.json`` (formats 3.0 and 3.1) deterministically.

Run from ``public_archive/``::

    uv run python scripts/make_test_vectors.py

Seeds, UUIDs and timestamps are fixed and Ed25519 signatures are
deterministic, so the output only changes when the format changes.  The seeds
are public test values, never real keys.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from pydantic import BaseModel

from indiek.core.author import Author
from indiek.core.canonical import canonical_bytes, digest, event_hash
from indiek.core.merkle import blob_root
from indiek.core.models import (
    CONTENTLESS_FORMAT_VERSION,
    FORMAT_VERSION,
    Edge,
    EventHeader,
    EventModel,
    MediaType,
    MetaEventHeader,
    MetaEventModel,
    MetaEventType,
    LogTip,
    Node,
    ResourceType,
    SealModel,
    Tag,
    Transcription,
)
from indiek.core.signing import sign_event, sign_object

OUTPUT = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "indiek"
    / "spec"
    / "test_vectors.json"
)
TIMESTAMP = datetime(2026, 10, 17, 12, 0, 0, tzinfo=UTC)
NODE_TEXT = "Gödel's incompleteness theorem"

RULES = {
    "canonical_bytes": (
        "RFC 8785 (JCS) restricted to ASCII object keys and integers in "
        "[-(2^53-1), 2^53-1]; inside that subset it equals "
        'json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False) '
        "encoded as UTF-8"
    ),
    "integer_range": (
        "every JSON number is an integer in [-(2^53-1), 2^53-1] "
        "(-9007199254740991 to 9007199254740991); writers refuse and readers "
        "reject any other number"
    ),
    "algorithms": (
        "header.hash_alg and header.sig_alg name the event's algorithms (today "
        "'sha256' and 'ed25519'); digests are written '<hash_alg>:<lowercase hex>' "
        "and signatures '<sig_alg>:<lowercase hex>'; the prev_hash and signature "
        "prefixes must equal the header's algorithms"
    ),
    "signature": (
        "'ed25519:' + lowercase hex Ed25519 (RFC 8032) signature over "
        "canonical_bytes(event without its 'signature' field), no pre-hash"
    ),
    "event_hash": (
        "'sha256:' + lowercase hex SHA-256 of canonical_bytes(whole event, "
        "'signature' included); it is the next event's header.prev_hash"
    ),
    "meta_anchor": (
        "a meta event's header.base_seq counts the base events its author had "
        "verified and header.base_head is the event_hash of base event number "
        "base_seq (null iff 0); base_seq never decreases along the meta log"
    ),
    "blob_root": (
        "RFC 6962 Merkle Tree Hash (SHA-256) over the ascending-sorted distinct "
        "blob digests referenced by the events a seal covers: leaf = "
        "SHA-256(0x00 || raw 32-byte digest), node = SHA-256(0x01 || left || "
        "right), no blobs = SHA-256(''); written 'sha256:<hex>'"
    ),
    "seal": (
        "sig = 'ed25519:' + Ed25519 over canonical_bytes(seal without 'sig'); "
        "seal hash = 'sha256:' + SHA-256 of canonical_bytes(whole seal)"
    ),
    "transcription": (
        "a transcription event attests its own log: verified_head must equal the "
        "event_hash of event number verified_count (1-based) of that log, and "
        "verified_count must be smaller than the transcription's own position"
    ),
    "strict_parsing": (
        "a log line that is not UTF-8, not one JSON object, or holds a duplicate "
        "key, a non-integer number (fraction, exponent, NaN, Infinity), an "
        "integer outside the range above or a string with a lone surrogate is "
        "invalid"
    ),
}


def _vector(name: str, seed_hex: str, event: BaseModel) -> dict[str, Any]:
    author = Author.from_seed_hex(seed_hex)
    unsigned = event.model_dump(mode="json")
    unsigned.pop("signature")
    signature = sign_event(unsigned, author)
    signed = {**unsigned, "signature": signature}
    return {
        "name": name,
        "seed_hex": seed_hex,
        "public_key_hex": author.public_key_hex,
        "event_unsigned": unsigned,
        "signing_bytes_hex": canonical_bytes(unsigned).hex(),
        "signature": signature,
        "event": signed,
        "event_hash": event_hash(signed),
    }


def build_vectors() -> list[dict[str, Any]]:
    alice_seed, bob_seed = "01" * 32, "02" * 32
    alice = Author.from_seed_hex(alice_seed).public_key_hex
    bob = Author.from_seed_hex(bob_seed).public_key_hex
    node_id = UUID("019a0000-0000-7000-8000-000000000001")

    genesis = _vector(
        "base genesis create_node, non-ASCII content and title",
        alice_seed,
        EventModel(
            header=EventHeader(prev_hash=None, timestamp=TIMESTAMP, author=alice),
            body=Node(
                node_id=node_id,
                title="Gödel — incompleteness",
                media_type=MediaType.TEXT_PLAIN,
                blob_hash="sha256:"
                + hashlib.sha256(NODE_TEXT.encode("utf-8")).hexdigest(),
            ),
        ),
    )
    chained = _vector(
        "base create_edge chained onto the genesis event",
        alice_seed,
        EventModel(
            header=EventHeader(
                prev_hash=genesis["event_hash"], timestamp=TIMESTAMP, author=alice
            ),
            body=Edge(
                edge_id=UUID("019a0000-0000-7000-8000-000000000002"),
                source_node=node_id,
                target_node=node_id,
                media_type=MediaType.TEXT_PLAIN,
                blob_hash="sha256:" + hashlib.sha256(b"refers to itself").hexdigest(),
            ),
        ),
    )
    meta = _vector(
        "meta genesis create_node_tag by a second author, anchored to base event 2",
        bob_seed,
        MetaEventModel(
            header=MetaEventHeader(
                prev_hash=None,
                timestamp=TIMESTAMP,
                author=bob,
                base_seq=2,
                base_head=chained["event_hash"],
            ),
            body=Tag(
                node_id=UUID("019a0000-0000-7000-8000-000000000003"),
                event_type=MetaEventType.CREATE_NODE_TAG,
                name="théorème",
                description="A proven statement",
            ),
        ),
    )
    transcription = _vector(
        "base transcription by a second author attesting the first two events",
        bob_seed,
        EventModel(
            header=EventHeader(
                prev_hash=chained["event_hash"], timestamp=TIMESTAMP, author=bob
            ),
            body=Transcription(
                verified_head=chained["event_hash"],
                verified_count=2,
                verified_hash_alg="sha256",
                verified_sig_alg="ed25519",
                verified_at=TIMESTAMP,
                note="re-verified",
            ),
        ),
    )
    content_less = _vector(
        "base content-less create_edge (format 3.1, resource_type none)",
        alice_seed,
        EventModel(
            header=EventHeader(
                version=CONTENTLESS_FORMAT_VERSION,
                prev_hash=transcription["event_hash"],
                timestamp=TIMESTAMP,
                author=alice,
            ),
            body=Edge(
                edge_id=UUID("019a0000-0000-7000-8000-000000000004"),
                source_node=node_id,
                target_node=node_id,
                resource_type=ResourceType.NONE,
            ),
        ),
    )
    return [genesis, chained, meta, transcription, content_less]


def build_merkle_vectors() -> list[dict[str, Any]]:
    """blob_root over 0, 1, 2, 3 and 5 digests (RFC 6962 tree shapes)."""
    vectors = []
    for n in (0, 1, 2, 3, 5):
        leaves = sorted(
            hashlib.sha256(f"blob {i}".encode()).hexdigest() for i in range(n)
        )
        vectors.append({"leaves": leaves, "root": blob_root(leaves)})
    return vectors


def build_seal_vectors(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One seal of the base vectors (genesis, chained, transcription) and the
    meta vector, by the first author."""
    genesis, chained, meta, transcription = events[:4]
    seed_hex = genesis["seed_hex"]
    author = Author.from_seed_hex(seed_hex)
    referenced = [
        e["event"]["body"]["blob_hash"]
        for e in (genesis, chained, transcription, meta)
        if e["event"]["body"].get("blob_hash")
    ]
    model = SealModel(
        seq=1,
        prev_seal_hash=None,
        base=LogTip(head=transcription["event_hash"], count=3),
        meta=LogTip(head=meta["event_hash"], count=1),
        blob_root=blob_root(referenced),
        time=TIMESTAMP,
        key=author.public_key_hex,
    )
    unsigned = model.model_dump(mode="json")
    unsigned.pop("sig")
    sig = sign_object(unsigned, author, "sig")
    signed = {**unsigned, "sig": sig}
    return [
        {
            "name": "first seal of the three base vectors and the meta vector",
            "seed_hex": seed_hex,
            "public_key_hex": author.public_key_hex,
            "seal_unsigned": unsigned,
            "signing_bytes_hex": canonical_bytes(unsigned).hex(),
            "sig": sig,
            "seal": signed,
            "seal_hash": digest(canonical_bytes(signed)),
        }
    ]


def main() -> None:
    document = {
        "format_version": FORMAT_VERSION,
        "description": (
            "Test vectors of the IndieK archive format: an independent implementation "
            "must reproduce every hex value from event_unsigned and seed_hex."
        ),
        "rules": RULES,
        "vectors": (vectors := build_vectors()),
        "merkle_vectors": build_merkle_vectors(),
        "seal_vectors": build_seal_vectors(vectors),
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    main()
