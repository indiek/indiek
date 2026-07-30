"""Generate and update the MANIFEST.json for an IndieK archive.

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
from pathlib import Path
from typing import Any, Dict, Optional

from ik.models import EVENT_FORMAT_VERSION

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
                "Format version string (e.g. '1.0').  Consumers MUST reject events "
                "whose version they do not recognise."
            ),
        },
        "prev_hash": {
            "type": "string | null",
            "description": (
                "SHA-256 hex digest (64 lower-case hex characters) of the *entire* "
                "preceding event JSON object, serialised with keys sorted "
                "alphabetically and no extra whitespace.  null for the genesis event."
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
                    "type": "string",
                    "enum": [
                        "text/plain; charset=utf-8",
                        "text/markdown; charset=utf-8",
                        "image/tiff",
                        "image/png",
                        "image/jpeg",
                    ],
                    "description": "MIME type of the blob referenced by blob_hash.",
                },
                "blob_hash": {
                    "type": "string",
                    "pattern": "^sha256:[0-9a-f]{64}$",
                    "description": (
                        "Content-address of the blob: 'sha256:' prefix followed by "
                        "the SHA-256 hex digest of the raw blob bytes."
                    ),
                },
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
                "media_type": {"$ref": "node.media_type"},
                "blob_hash": {"$ref": "node.blob_hash"},
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

_EVENT_MODEL_SCHEMA: Dict[str, Any] = {
    "description": "Top-level structure of every NDJSON line in the base event log.",
    "fields": {
        "header": {"$ref": "EventHeader"},
        "body": {"$ref": "EventBody"},
        "signature": {
            "type": "string | null",
            "description": (
                "Hex-encoded Ed25519 signature produced by signing the SHA-256 "
                "digest of the body serialised as compact JSON with keys sorted "
                "alphabetically."
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
        "Each event's header.prev_hash is the SHA-256 of the *entire* preceding "
        "event JSON (keys sorted, compact).  The genesis event has prev_hash=null.  "
        "The hash of the final event is the canonical unique identifier for the "
        "archive at that point in time: two archives are identical iff their last "
        "event hashes match."
    ),
    "signature_algorithm": {
        "signing_curve": "Ed25519",
        "library_reference": "PyNaCl / libsodium",
        "what_is_signed": (
            "SHA-256 digest of the event body serialised as compact JSON with "
            "keys sorted alphabetically (json.dumps(body, sort_keys=True))."
        ),
        "signature_encoding": "lowercase hex string",
    },
}

# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def generate_manifest(
    archive_root: str | Path,
    author_public_keys: Optional[list[str]] = None,
) -> Path:
    """Write (or overwrite) MANIFEST.json at the archive root.

    Args:
        archive_root: Path to the root of the archive (same directory that
            contains ``blobs/`` and ``events/``).
        author_public_keys: List of 64-char hex Ed25519 public keys that are
            authorised to write events to this archive.  If omitted, the
            manifest is written with an empty authors list.

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
        "blob_store": _BLOB_STORE_LAYOUT,
        "event_log": _EVENT_LOG_LAYOUT,
        "schemas": {
            "EventHeader": _EVENT_HEADER_SCHEMA,
            "EventBody": _EVENT_BODY_SCHEMA,
            "MetaEventBody": _META_EVENT_BODY_SCHEMA,
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
