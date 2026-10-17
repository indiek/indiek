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

Generate and update the MANIFEST.json for an IndieK archive.

The MANIFEST.json file is meant to be shipped alongside every archive so that
any consumer — regardless of what software they are running — can understand
how to parse the event log and the blob store without access to the original
code or documentation.

Design principle: the MANIFEST is a human- and machine-readable document that
describes the *structure* of the archive.  It does NOT duplicate event data.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Dict, Optional

from indiek.core.canonical import algorithm_of
from indiek.core.models import EVENT_FORMAT_VERSION

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Canonical schema snapshots (kept in sync with models.py by hand)
# ---------------------------------------------------------------------------

_EVENT_HEADER_SCHEMA: Dict[str, Any] = {
    "description": "Header present in every event and meta-event.",
    "fields": {
        "version": {
            "type": "string",
            "description": (
                "Format version string ('3.0'). Consumers MUST reject events "
                "whose version they do not recognise."
            ),
        },
        "hash_alg": {
            "type": "string",
            "enum": ["sha256"],
            "description": (
                "Hash algorithm of this event: prev_hash is computed with it and "
                "MUST carry it as prefix; the event's own hash also uses it."
            ),
        },
        "sig_alg": {
            "type": "string",
            "enum": ["ed25519"],
            "description": (
                "Signature algorithm of this event; the signature MUST carry it "
                "as prefix."
            ),
        },
        "prev_hash": {
            "type": "string | null",
            "pattern": "^<hash_alg>:<lowercase hex>$",
            "description": (
                "'<hash_alg>:<hex>' digest, under this event's hash_alg, of the "
                "canonical bytes of the *entire* preceding event, signature included "
                "(see event_log.canonical_bytes).  null for the first event of a "
                "log, and only there."
            ),
        },
        "timestamp": {
            "type": "string",
            "format": "ISO-8601 datetime with timezone",
            "description": "Wall-clock time at which the event was written by the author.",
        },
        "author": {
            "type": "string",
            "description": (
                "64-character hex-encoded Ed25519 public key of the event author.  "
                "This key MUST appear in MANIFEST.json > authors."
            ),
        },
    },
}

_EVENT_BODY_SCHEMA: Dict[str, Any] = {
    "description": (
        "Body of a base-network event.  Exactly one of the body types below "
        "is present, discriminated by the body_type field."
    ),
    "body_types": {
        "node": {
            "discriminator": "body_type = 'node'",
            "fields": {
                "body_type": {"const": "node"},
                "event_type": {"const": "create_node"},
                "node_id": {
                    "type": "UUID v7 string",
                    "description": "Unique identifier for the node.",
                },
                "title": {
                    "type": "string | null",
                    "description": "Optional human-readable title.",
                },
                "media_type": {
                    "type": "string | null",
                    "enum": [
                        "text/plain; charset=utf-8",
                        "text/markdown; charset=utf-8",
                        "image/tiff",
                        "image/png",
                        "image/jpeg",
                        "application/pdf; profile=pdfa",
                    ],
                    "description": "Required for managed and local_file resources; optional URI hint.",
                },
                "resource_type": {
                    "type": "string",
                    "enum": ["managed", "uri", "local_file"],
                    "default": "managed",
                    "description": "Missing in format 1.0 events implies managed.",
                },
                "blob_hash": {
                    "type": "string | null",
                    "pattern": "^sha256:[0-9a-f]{64}$",
                    "description": (
                        "Content-address of the managed blob. Present only when "
                        "resource_type is managed."
                    ),
                },
                "uri": {
                    "type": "string | null",
                    "description": "Required external URI when resource_type is uri.",
                },
                "path": {
                    "type": "string | null",
                    "description": "Required local path when resource_type is local_file.",
                },
                "file_size": {
                    "type": "integer | null",
                    "minimum": 0,
                    "description": "Verified byte length for local_file.",
                },
                "file_hash": {
                    "type": "string | null",
                    "pattern": "^sha256:[0-9a-f]{64}$",
                    "description": "SHA-256 fingerprint for local_file.",
                },
                "last_verified": {
                    "type": "string | null",
                    "format": "ISO-8601 datetime",
                    "description": "Time local_file metadata was last verified.",
                },
            },
            "resource_rules": {
                "managed": "requires blob_hash and media_type; excludes uri/local-file fields",
                "uri": "requires uri; media_type is an optional hint; excludes blob_hash/local-file fields",
                "local_file": "requires path, file_size, file_hash, last_verified, and media_type; excludes uri/blob_hash",
            },
        },
        "edge": {
            "discriminator": "body_type = 'edge'",
            "fields": {
                "body_type": {"const": "edge"},
                "event_type": {"const": "create_edge"},
                "edge_id": {"type": "UUID v7 string"},
                "source_node": {
                    "type": "UUID v7 string",
                    "description": "node_id of the edge's source node.",
                },
                "target_node": {
                    "type": "UUID v7 string",
                    "description": "node_id of the edge's target node.",
                },
                "title": {"type": "string | null"},
                "resource_type": {"$ref": "node.resource_type"},
                "media_type": {"$ref": "node.media_type"},
                "blob_hash": {"$ref": "node.blob_hash"},
                "uri": {"$ref": "node.uri"},
                "path": {"$ref": "node.path"},
                "file_size": {"$ref": "node.file_size"},
                "file_hash": {"$ref": "node.file_hash"},
                "last_verified": {"$ref": "node.last_verified"},
            },
        },
        "supersede_node": {
            "discriminator": "body_type = 'supersede_node'",
            "fields": {
                "body_type": {"const": "supersede_node"},
                "event_type": {"const": "supersede_node"},
                "node_id": {
                    "type": "UUID v7 string",
                    "description": "ID of an existing node to supersede.",
                },
                "title": {"type": "string | null"},
                "resource_type": {"$ref": "node.resource_type"},
                "media_type": {"$ref": "node.media_type"},
                "blob_hash": {"$ref": "node.blob_hash"},
                "uri": {"$ref": "node.uri"},
                "path": {"$ref": "node.path"},
                "file_size": {"$ref": "node.file_size"},
                "file_hash": {"$ref": "node.file_hash"},
                "last_verified": {"$ref": "node.last_verified"},
            },
        },
        "transcription": {"$ref": "TranscriptionBody"},
        "supersede_edge": {
            "discriminator": "body_type = 'supersede_edge'",
            "fields": {
                "body_type": {"const": "supersede_edge"},
                "event_type": {"const": "supersede_edge"},
                "edge_id": {
                    "type": "UUID v7 string",
                    "description": "ID of an existing edge to supersede.",
                },
                "source_node": {
                    "type": "UUID v7 string",
                    "description": "Must equal the existing edge source.",
                },
                "target_node": {
                    "type": "UUID v7 string",
                    "description": "Must equal the existing edge target.",
                },
                "title": {"type": "string | null"},
                "resource_type": {"$ref": "node.resource_type"},
                "media_type": {"$ref": "node.media_type"},
                "blob_hash": {"$ref": "node.blob_hash"},
                "uri": {"$ref": "node.uri"},
                "path": {"$ref": "node.path"},
                "file_size": {"$ref": "node.file_size"},
                "file_hash": {"$ref": "node.file_hash"},
                "last_verified": {"$ref": "node.last_verified"},
            },
        },
    },
}

_META_EVENT_BODY_SCHEMA: Dict[str, Any] = {
    "description": (
        "Body of a meta-network event.  The meta-network encodes node/edge tagging "
        "as a graph of its own.  body_type discriminates the variant."
    ),
    "body_types": {
        "tag": {
            "discriminator": "body_type = 'tag'",
            "event_types": ["create_node_tag", "create_edge_tag"],
            "fields": {
                "body_type": {"const": "tag"},
                "event_type": {"enum": ["create_node_tag", "create_edge_tag"]},
                "node_id": {"type": "UUID v7 string"},
                "name": {"type": "string"},
                "description": {"type": "string"},
            },
        },
        "representation": {
            "discriminator": "body_type = 'representation'",
            "event_types": [
                "create_node_representation",
                "create_edge_representation",
            ],
            "description": (
                "A shadow node in the meta-network that stands for a base-network "
                "node or edge, allowing tags to be attached via meta-edges."
            ),
            "fields": {
                "body_type": {"const": "representation"},
                "event_type": {
                    "enum": [
                        "create_node_representation",
                        "create_edge_representation",
                    ]
                },
                "node_id": {"type": "UUID v7 string"},
                "underlying_id": {
                    "type": "UUID v7 string",
                    "description": "ID of the base-network node or edge being represented.",
                },
            },
        },
        "transcription": {"$ref": "TranscriptionBody"},
        "edge": {
            "discriminator": "body_type = 'edge'",
            "event_types": ["set_node_tag", "set_edge_tag"],
            "description": (
                "A directed edge in the meta-network from a tag node to a "
                "representation node, meaning: 'this tag is applied to that item'."
            ),
            "fields": {
                "body_type": {"const": "edge"},
                "event_type": {"enum": ["set_node_tag", "set_edge_tag"]},
                "edge_id": {"type": "UUID v7 string"},
                "source_node": {
                    "type": "UUID v7 string",
                    "description": "node_id of the tag.",
                },
                "target_node": {
                    "type": "UUID v7 string",
                    "description": "node_id of the representation.",
                },
            },
        },
    },
}

_TRANSCRIPTION_BODY_SCHEMA: Dict[str, Any] = {
    "description": (
        "An attestation allowed in the base AND in the meta log: 'I verified this "
        "log up to verified_head (its first verified_count events) under "
        "verified_hash_alg / verified_sig_alg at verified_at'.  It attests only "
        "the log it sits in, allocates no alias and changes no projection.  "
        "Verification rejects it unless 1 <= verified_count < its own position and "
        "verified_head equals the hash of event number verified_count of that log."
    ),
    "fields": {
        "body_type": {"const": "transcription"},
        "event_type": {"const": "transcription"},
        "verified_head": {"type": "string", "pattern": "^<hash_alg>:<hex>$"},
        "verified_count": {"type": "integer", "minimum": 1},
        "verified_hash_alg": {"type": "string"},
        "verified_sig_alg": {"type": "string"},
        "verified_at": {"type": "string", "format": "ISO-8601 datetime"},
        "note": {"type": "string | null"},
    },
}

_EVENT_MODEL_SCHEMA: Dict[str, Any] = {
    "description": "Top-level structure of every NDJSON line in the base event log.",
    "fields": {
        "header": {"$ref": "EventHeader"},
        "body": {"$ref": "EventBody"},
        "signature": {
            "type": "string | null",
            "description": (
                "'ed25519:<lowercase hex>' Ed25519 signature of the canonical bytes "
                "of the whole event without its signature field ({header, body}); "
                "no pre-hash.  The prefix MUST equal header.sig_alg."
            ),
        },
    },
}

_META_EVENT_MODEL_SCHEMA: Dict[str, Any] = {
    "description": "Top-level structure of every NDJSON line in the meta event log.",
    "fields": {
        "header": {"$ref": "EventHeader"},
        "body": {"$ref": "MetaEventBody"},
        "signature": {"$ref": "EventModel.signature"},
    },
}

# ---------------------------------------------------------------------------
# Blob store layout description
# ---------------------------------------------------------------------------

_BLOB_STORE_LAYOUT: Dict[str, Any] = {
    "description": (
        "Content-addressed blob store.  Every blob is immutable once written."
    ),
    "root": "<archive_root>/blobs/sha256/",
    "path_pattern": "<root>/<hex[0:2]>/<hex[2:4]>/<sha256_hex>",
    "example": "blobs/sha256/ab/cd/abcd1234...ef",
    "notes": [
        "The filename is the full 64-character SHA-256 hex digest of the blob bytes.",
        "The two-level sharding (first 2 + next 2 hex chars) keeps directories small.",
        "To retrieve a blob referenced by 'sha256:XXXX' in an event, strip the "
        "'sha256:' prefix and navigate to blobs/sha256/<XXXX[0:2]>/<XXXX[2:4]>/<XXXX>.",
    ],
}

# ---------------------------------------------------------------------------
# Event log layout description
# ---------------------------------------------------------------------------

_EVENT_LOG_LAYOUT: Dict[str, Any] = {
    "description": (
        "Append-only event log stored as date-sharded NDJSON files.  "
        "Reading ALL files in chronological order (by filesystem path) "
        "produces the complete, ordered event sequence."
    ),
    "base_event_log_root": "<archive_root>/events/",
    "meta_event_log_root": "<archive_root>/meta/events/",
    "path_pattern": "<log_root>/YYYY/MM/DD/events.ndjson",
    "file_format": "NDJSON (one JSON object per line, UTF-8 encoded)",
    "ordering": (
        "Sort all ndjson file paths lexicographically before reading.  "
        "Within a file, events are in append order (top = oldest)."
    ),
    "chain_integrity": (
        "Each event's header.prev_hash is the '<hash_alg>:<hex>' digest, under that "
        "event's header.hash_alg, of the canonical bytes of the *entire* preceding "
        "event (signature included).  The first event of a "
        "log has prev_hash=null, and no other event may.  "
        "The hash of the final event is the canonical unique identifier for the "
        "archive at that point in time: two archives are identical iff their last "
        "event hashes match."
    ),
    "canonical_bytes": (
        'json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False) '
        "encoded as UTF-8: compact, keys sorted recursively, non-ASCII kept as raw "
        "UTF-8.  Test vectors ship in the indiek package (indiek/spec/test_vectors.json)."
    ),
    "strict_parsing": (
        "A log line is invalid if it is not one JSON object, repeats a key in any "
        "object, or contains a non-integer number (float, exponent, NaN, Infinity)."
    ),
    "signature_algorithm": {
        "signing_curve": "Ed25519",
        "specification": "RFC 8032 (PureEd25519)",
        "library_reference": "PyNaCl / libsodium",
        "what_is_signed": (
            "The canonical bytes of the whole event without its signature field "
            "({header, body}), signed directly (no pre-hash).  Signing the header "
            "binds each signature to its chain position, time and author."
        ),
        "signature_encoding": "'ed25519:' followed by 128 lowercase hex characters",
    },
    "algorithm_agility": (
        "Every digest is written '<hash_alg>:<lowercase hex>' and every signature "
        "'<sig_alg>:<lowercase hex>'.  Each event names its algorithms in "
        "header.hash_alg and header.sig_alg; its prev_hash and signature prefixes "
        "MUST equal them.  Unknown algorithms or mismatched prefixes make the "
        "archive invalid.  Supported today: hash sha256, signature ed25519.  "
        "Blob hashes keep the 'sha256:' prefix.  Transcription events let later "
        "authors re-attest a log under newer algorithms."
    ),
}

# ---------------------------------------------------------------------------
# Public entry point
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


def write_manifest(
    archive_root: str | Path,
    author_public_keys: Optional[list[str]] = None,
    algorithms: Optional[dict[str, list[str]]] = None,
) -> Path:
    """Write (or overwrite) MANIFEST.json at the archive root.

    Args:
        archive_root: Path to the root of the archive (same directory that
            contains ``blobs/`` and ``events/``).
        author_public_keys: List of 64-char hex Ed25519 public keys that are
            authorised to write events to this archive.  If omitted, the
            manifest is written with an empty authors list.
        algorithms: ``{"hash": [...], "signature": [...]}`` listing every
            algorithm used in the archive (see :func:`collect_algorithms`).
            Defaults to empty lists.

    Returns:
        The path to the written MANIFEST.json file.
    """
    root = Path(archive_root).expanduser().resolve()
    manifest: Dict[str, Any] = {
        "format": "IndieK Public Archive",
        "format_version": EVENT_FORMAT_VERSION,
        "description": (
            "This MANIFEST.json documents the layout and schemas of an IndieK "
            "archive.  It is intended to allow any consumer to parse the archive "
            "independently of the original software, now or in the future."
        ),
        "authors": [
            {"public_key": key, "algorithm": "Ed25519"}
            for key in (author_public_keys or [])
        ],
        "algorithms": algorithms or {"hash": [], "signature": []},
        "blob_store": _BLOB_STORE_LAYOUT,
        "event_log": _EVENT_LOG_LAYOUT,
        "schemas": {
            "EventHeader": _EVENT_HEADER_SCHEMA,
            "EventBody": _EVENT_BODY_SCHEMA,
            "MetaEventBody": _META_EVENT_BODY_SCHEMA,
            "TranscriptionBody": _TRANSCRIPTION_BODY_SCHEMA,
            "EventModel": _EVENT_MODEL_SCHEMA,
            "MetaEventModel": _META_EVENT_MODEL_SCHEMA,
        },
    }

    manifest_path = root / "MANIFEST.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    logger.info(f"MANIFEST written to {manifest_path}")
    return manifest_path
