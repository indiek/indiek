"""Copyright 2026 Adrian Ernesto Radillo

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

---

Generate ``MANIFEST.json`` and copy the format specification into an archive.

``ik manifest`` writes three informative files at the archive root so that
any consumer, now or in a thousand years, can parse the archive without the
original software (seal.md, item 2):

* ``MANIFEST.json``: machine-readable layout, rules and JSON Schemas of every
  log line.  The schemas are generated from the pydantic models
  (``model_json_schema``), so they cannot drift from the code.
* ``SPEC.md``: the normative, human-readable specification (owner decision D19).
* ``test_vectors.json``: vectors an independent implementation must reproduce.

Design principle: the MANIFEST describes the *structure* of the archive; it
never duplicates event data.  None of the three files affects validity."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from pydantic.json_schema import models_json_schema

from indiek.core.canonical import MAX_SAFE_INTEGER, algorithm_of
from indiek.core.models import (
    EVENT_FORMAT_VERSION,
    EventModel,
    MetaEventModel,
    SealModel,
)
from indiek.core.spec import SPEC_FILES, packaged_spec_file

logger = logging.getLogger(__name__)

SCHEMA_REF_TEMPLATE = "#/schemas/{model}"

# ---------------------------------------------------------------------------
# Archive root (owner decision D21)
# ---------------------------------------------------------------------------

_ARCHIVE_LAYOUT: dict[str, Any] = {
    "description": (
        "Entries of the archive root.  Only events/ is needed for a non-empty "
        "archive (plus blobs/ as soon as an event references a blob); every "
        "other entry is optional.  The event logs and the blobs are the only "
        "source of truth: indexes, aliases and caches are rebuildable views."
    ),
    "entries": {
        "MANIFEST.json": "This file (informative, written by 'ik manifest').",
        "SPEC.md": (
            "Normative, human-readable format specification (informative copy)."
        ),
        "test_vectors.json": "Test vectors of the format (informative copy).",
        "events/": "Base event log: the knowledge graph (nodes and edges).",
        "meta/events/": "Meta event log: tags and their assignments.",
        "seals/": "Seal log: signed checkpoints of the whole archive.",
        "blobs/": "Content-addressed blob store (blobs/sha256/...).",
    },
    "not_part_of_the_archive": (
        "The verification cache lives in the reader's user cache directory, "
        "never in the archive; a .ik-cache/ folder, or any other entry not "
        "listed above, is ignored."
    ),
}

# ---------------------------------------------------------------------------
# Blob store
# ---------------------------------------------------------------------------

_BLOB_STORE_LAYOUT: dict[str, Any] = {
    "description": (
        "Content-addressed blob store.  Every blob is immutable once written."
    ),
    "root": "<archive_root>/blobs/sha256/",
    "path_pattern": "<root>/<hex[0:2]>/<hex[2:4]>/<sha256_hex>",
    "example": "blobs/sha256/ab/cd/abcd1234...ef",
    "notes": [
        "The filename is the full 64-character lowercase SHA-256 hex digest of "
        "the blob bytes.",
        "The two-level sharding (first 2 + next 2 hex chars) keeps directories small.",
        "To retrieve a blob referenced by 'sha256:XXXX' in an event, strip the "
        "'sha256:' prefix and open blobs/sha256/<XXXX[0:2]>/<XXXX[2:4]>/<XXXX>.",
        "A referenced blob that is missing, or whose bytes hash to something "
        "else, makes the archive invalid.",
    ],
}

# ---------------------------------------------------------------------------
# Event logs
# ---------------------------------------------------------------------------

_EVENT_LOG_LAYOUT: dict[str, Any] = {
    "description": (
        "Two append-only, hash-chained event logs stored as date-sharded NDJSON "
        "files: the base log (the knowledge graph) and the meta log (tags)."
    ),
    "base_event_log_root": "<archive_root>/events/",
    "meta_event_log_root": "<archive_root>/meta/events/",
    "path_pattern": "<log_root>/YYYY/MM/DD/events.ndjson (UTC date of the event)",
    "file_format": (
        "NDJSON: one JSON object per line, UTF-8, each line terminated by LF"
    ),
    "ordering": (
        "Sort every file whose name ends in 'ndjson' under the log root by "
        "path, lexicographically, then read each file top to bottom.  The "
        "result is the event sequence; event numbers start at 1."
    ),
    "chain_integrity": (
        "Each event's header.prev_hash is the '<hash_alg>:<hex>' digest, under "
        "that event's header.hash_alg, of the canonical bytes of the *entire* "
        "preceding event (signature included).  The first event of a log has "
        "prev_hash=null, and no other event may.  The hash of the last event is "
        "the head of the log."
    ),
    "canonical_bytes": (
        "RFC 8785 (JSON Canonicalization Scheme) restricted to ASCII object keys "
        f"and integers in [-(2^53-1), 2^53-1] ({MAX_SAFE_INTEGER}); no other "
        "numbers are allowed.  Inside that subset it equals Python's "
        'json.dumps(obj, sort_keys=True, separators=(",", ":"), '
        "ensure_ascii=False) encoded as UTF-8: no whitespace, keys sorted, "
        "non-ASCII characters kept as raw UTF-8.  Hashes and signatures are "
        "computed over the canonical bytes of the parsed line, never over the "
        "bytes on disk.  See SPEC.md and test_vectors.json."
    ),
    "strict_parsing": (
        "A log line is invalid if it is not UTF-8, is not one JSON object, "
        "repeats a key in any object, contains a non-integer number (fraction, "
        "exponent, NaN, Infinity) or an integer outside [-(2^53-1), 2^53-1], or "
        "holds a string with a lone surrogate."
    ),
    "signature_algorithm": {
        "signing_curve": "Ed25519",
        "specification": "RFC 8032 (PureEd25519)",
        "what_is_signed": (
            "The canonical bytes of the whole event without its signature field "
            "({header, body}), signed directly (no pre-hash).  Signing the header "
            "binds each signature to its chain position, time and author."
        ),
        "signature_encoding": "'ed25519:' followed by 128 lowercase hex characters",
        "public_key": "header.author: 64 lowercase hex characters (32 bytes)",
    },
    "meta_anchors": (
        "Verify the base log first, keeping the hash of every base event.  Then "
        "every meta event's (base_seq, base_head) must name a base event that "
        "exists with exactly that hash (base_seq 0 with base_head null for an "
        "empty view), and base_seq must not decrease along the meta log.  Meta "
        "commits to base; base never commits to meta."
    ),
    "algorithm_agility": (
        "Every digest is written '<hash_alg>:<lowercase hex>' and every signature "
        "'<sig_alg>:<lowercase hex>'.  Each event names its algorithms in "
        "header.hash_alg and header.sig_alg; its prev_hash and signature prefixes "
        "MUST equal them.  Unknown algorithms or mismatched prefixes make the "
        "archive invalid.  Supported: hash sha256, signature ed25519.  Blob "
        "hashes are always 'sha256:'.  Transcription events let later authors "
        "re-attest a log under newer algorithms."
    ),
}

# ---------------------------------------------------------------------------
# Seal log
# ---------------------------------------------------------------------------

_SEAL_LOG_LAYOUT: dict[str, Any] = {
    "description": (
        "Append-only log of signed checkpoints ('seals'), one JSON object per "
        "line.  The hash of the latest seal is the one string that commits to "
        "the whole archive: publish it, and check it with 'ik verify --expect'."
    ),
    "path": "<archive_root>/seals/seals.ndjson",
    "file_format": "NDJSON, UTF-8, parsed with the same strict rules as event logs",
    "signing": (
        "sig = 'ed25519:<hex>' Ed25519 signature by 'key' over the canonical bytes "
        "of the seal without its 'sig' field.  Seal hash = '<hash_alg>:<hex>' digest "
        "of the canonical bytes of the whole seal (sig included)."
    ),
    "chain": (
        "seq is the 1-based position of the seal; prev_seal_hash is the hash of "
        "the previous seal, null for the first seal and only there."
    ),
    "tips": (
        "base and meta are {head, count}: head MUST be the hash of event number "
        "count of that verified log (null iff count is 0).  Counts MUST NOT "
        "decrease along the seal log."
    ),
    "blob_root": (
        "RFC 6962 Merkle Tree Hash, with SHA-256, over the ascending-sorted list "
        "of distinct blob digests referenced (blob_hash) by the first base.count "
        "base events and the first meta.count meta events.  Leaf = "
        "SHA-256(0x00 || 32 raw digest bytes); inner node = SHA-256(0x01 || left "
        "|| right), pairing level by level and promoting an odd last node "
        "unchanged; no blobs = SHA-256 of the empty string.  Written "
        "'sha256:<hex>'.  Every seal is checked."
    ),
    "unreferenced_blobs": (
        "Files under blobs/sha256/ that no event references (an interrupted "
        "write, or a file added by hand) are not covered by any seal.  Readers "
        "SHOULD warn about them; writers MUST NOT seal while any exist.  They "
        "are safe to delete."
    ),
    "warnings": (
        "A seal of an empty archive, or a seal committing to the same tips and "
        "blob_root as the previous seal, is valid but SHOULD be reported."
    ),
}

# ---------------------------------------------------------------------------
# Verification levels and the cache (reader behaviour, informative)
# ---------------------------------------------------------------------------

_VERIFICATION: dict[str, Any] = {
    "description": (
        "Reader behaviour of the reference implementation (informative).  The "
        "validity of an archive is defined by SPEC.md alone."
    ),
    "levels": {
        "none": ("Parse only (debugging, recovery); the archive is opened read-only."),
        "incremental": (
            "Recompute every hash link, anchor, transcription and seal; skip "
            "only the signature checks and blob re-hashing that the reader's own "
            "cache, or a seal hash the reader supplied, vouches for."
        ),
        "full": "Check everything, then refresh the reader's cache.",
    },
    "trust": (
        "Checks may be skipped only on the basis of (a) the reader's own cache "
        "or (b) a seal hash obtained by the reader through a separate, trusted "
        "route.  A seal found in the archive is always checked, never trusted."
    ),
    "cache": (
        "The cache is local to the reader, non-authoritative and regenerable.  "
        "It lives outside the archive, in the user's cache directory, so that "
        "nothing shipped with an archive can make a reader skip a check."
    ),
}


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


def generate_schemas() -> dict[str, Any]:
    """JSON Schemas of every log line and of every model they use, keyed by
    model name; ``$ref`` values point to ``#/schemas/<name>`` so they resolve
    inside ``MANIFEST.json``."""
    _, document = models_json_schema(
        [
            (EventModel, "validation"),
            (MetaEventModel, "validation"),
            (SealModel, "validation"),
        ],
        ref_template=SCHEMA_REF_TEMPLATE,
    )
    return dict(sorted(document["$defs"].items()))


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def collect_algorithms(events: Iterable[dict[str, Any]]) -> dict[str, list[str]]:
    """Sorted hash and signature algorithm names appearing in ``events``."""
    hashes: set[str] = set()
    signatures: set[str] = set()
    for event in events:
        header, body = event.get("header", {}), event.get("body", {})
        hashes.add(header.get("hash_alg") or "")
        signatures.add(header.get("sig_alg") or "")
        for value in (
            header.get("prev_hash"),
            body.get("blob_hash"),
            body.get("file_hash"),
            body.get("verified_head"),
        ):
            if isinstance(value, str):
                hashes.add(algorithm_of(value))
        hashes.add(body.get("verified_hash_alg") or "")
        signatures.add(body.get("verified_sig_alg") or "")
        if isinstance(event.get("signature"), str):
            signatures.add(algorithm_of(event["signature"]))
    return {
        "hash": sorted(hashes - {""}),
        "signature": sorted(signatures - {""}),
    }


def build_manifest(
    author_public_keys: list[str] | None = None,
    algorithms: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """The ``MANIFEST.json`` document (no event data)."""
    return {
        "format": "IndieK Public Archive",
        "format_version": EVENT_FORMAT_VERSION,
        "description": (
            "This MANIFEST.json documents the layout and schemas of an IndieK "
            "archive.  It is intended to allow any consumer to parse the archive "
            "independently of the original software, now or in the future.  "
            "SPEC.md, next to it, is the normative specification."
        ),
        "spec": {"normative": "SPEC.md", "test_vectors": "test_vectors.json"},
        "authors": [
            {"public_key": key, "algorithm": "Ed25519"}
            for key in (author_public_keys or [])
        ],
        "authors_note": (
            "Informative: the key of whoever ran 'ik manifest'.  Every event "
            "names its own author in header.author; validity never depends on "
            "this list."
        ),
        "algorithms": algorithms or {"hash": [], "signature": []},
        "archive_layout": _ARCHIVE_LAYOUT,
        "blob_store": _BLOB_STORE_LAYOUT,
        "event_log": _EVENT_LOG_LAYOUT,
        "seal_log": _SEAL_LOG_LAYOUT,
        "verification": _VERIFICATION,
        "log_lines": {
            "events/": SCHEMA_REF_TEMPLATE.format(model="EventModel"),
            "meta/events/": SCHEMA_REF_TEMPLATE.format(model="MetaEventModel"),
            "seals/": SCHEMA_REF_TEMPLATE.format(model="SealModel"),
        },
        "schemas": generate_schemas(),
    }


def write_manifest(
    archive_root: str | Path,
    author_public_keys: list[str] | None = None,
    algorithms: dict[str, list[str]] | None = None,
) -> Path:
    """Write (or overwrite) ``MANIFEST.json``, ``SPEC.md`` and
    ``test_vectors.json`` at the archive root.

    Args:
        archive_root: Root of the archive (the directory holding ``events/``).
        author_public_keys: 64-char hex Ed25519 public keys to list as
            ``authors`` (informative).  Defaults to an empty list.
        algorithms: ``{"hash": [...], "signature": [...]}`` listing every
            algorithm used in the archive (see :func:`collect_algorithms`).
            Defaults to empty lists.

    Returns:
        The path to the written ``MANIFEST.json``.
    """
    root = Path(archive_root).expanduser().resolve()
    manifest_path = root / "MANIFEST.json"
    manifest_path.write_text(
        json.dumps(
            build_manifest(author_public_keys, algorithms),
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    for name in SPEC_FILES:
        (root / name).write_bytes(packaged_spec_file(name))
    logger.info("MANIFEST, %s written to %s", ", ".join(SPEC_FILES), root)
    return manifest_path
