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

Canonical serialisation, algorithm-prefixed digests and signatures, and
strict parsing of log lines (format 3.0).

* Canonical bytes: ``json.dumps(obj, sort_keys=True, separators=(",", ":"),
  ensure_ascii=False)`` encoded as UTF-8.  Pydantic models are first dumped
  with ``model_dump(mode="json")``.
* Algorithm agility: every digest is written ``<hash_alg>:<lowercase hex>``
  (e.g. ``sha256:…``) and every signature ``<sig_alg>:<lowercase hex>`` (e.g.
  ``ed25519:…``).  An event names its algorithms in ``header.hash_alg`` and
  ``header.sig_alg``; its ``prev_hash`` and ``signature`` prefixes must match.
* Event hash: digest, under a given ``hash_alg``, of the canonical bytes of
  the whole event (``header``, ``body`` and ``signature``).  The next event's
  ``header.prev_hash`` holds it, computed with *that* event's ``hash_alg``.
* Log lines are parsed strictly: duplicate object keys, floats and the
  non-standard constants ``NaN``/``Infinity`` make a line invalid, because
  implementations disagree on how to read or re-serialise them."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from typing import Any, NoReturn

from pydantic import BaseModel

from indiek.core.errors import IntegrityError

DEFAULT_HASH_ALG = "sha256"
DEFAULT_SIG_ALG = "ed25519"

# Supported algorithms: hash name -> constructor; signature name -> byte length.
HASH_ALGORITHMS: dict[str, Callable[[bytes], Any]] = {"sha256": hashlib.sha256}
SIGNATURE_ALGORITHMS: dict[str, int] = {"ed25519": 64}

_LOWER_HEX = re.compile(r"[0-9a-f]*")


def json_ready(obj: Mapping[str, Any] | BaseModel) -> dict[str, Any]:
    """Plain JSON-compatible ``dict`` of a mapping or a pydantic model."""
    if isinstance(obj, BaseModel):
        return obj.model_dump(mode="json")
    return dict(obj)


def canonical_bytes(obj: Mapping[str, Any] | BaseModel) -> bytes:
    """Return the canonical bytes of ``obj`` (see the module docstring)."""
    return json.dumps(
        json_ready(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def algorithm_of(value: str) -> str:
    """The ``<alg>`` prefix of an ``<alg>:<hex>`` string (``""`` if none)."""
    alg, sep, _ = value.partition(":")
    return alg if sep else ""


def digest(data: bytes, hash_alg: str = DEFAULT_HASH_ALG) -> str:
    """Prefixed digest ``<hash_alg>:<hex>`` of ``data``."""
    try:
        constructor = HASH_ALGORITHMS[hash_alg]
    except KeyError:
        raise IntegrityError(f"Unsupported algorithm {hash_alg!r}") from None
    return f"{hash_alg}:{constructor(data).hexdigest()}"


def event_hash(
    event: Mapping[str, Any] | BaseModel, hash_alg: str = DEFAULT_HASH_ALG
) -> str:
    """Prefixed digest of the canonical bytes of the whole event."""
    return digest(canonical_bytes(event), hash_alg)


def _split(value: object, kind: str) -> tuple[str, str]:
    if not isinstance(value, str) or ":" not in value:
        raise IntegrityError(f"Malformed {kind} {value!r}: expected '<alg>:<hex>'")
    alg, _, hex_part = value.partition(":")
    if not hex_part or _LOWER_HEX.fullmatch(hex_part) is None:
        raise IntegrityError(f"Malformed {kind} {value!r}: not lowercase hex")
    return alg, hex_part


def parse_digest(value: str) -> tuple[str, str]:
    """Split ``<hash_alg>:<hex>`` into ``(hash_alg, hex)``.

    Raises:
        IntegrityError: malformed value, unknown algorithm or wrong length.
    """
    alg, hex_part = _split(value, "digest")
    if alg not in HASH_ALGORITHMS:
        raise IntegrityError(f"Unsupported algorithm {alg!r}")
    if len(hex_part) != 2 * HASH_ALGORITHMS[alg]().digest_size:
        raise IntegrityError(f"Malformed digest {value!r}: wrong length")
    return alg, hex_part


def parse_signature(value: str) -> tuple[str, bytes]:
    """Split ``<sig_alg>:<hex>`` into ``(sig_alg, signature bytes)``.

    Raises:
        IntegrityError: malformed value, unknown algorithm or wrong length.
    """
    alg, hex_part = _split(value, "signature")
    if alg not in SIGNATURE_ALGORITHMS:
        raise IntegrityError(f"Unsupported algorithm {alg!r}")
    if len(hex_part) != 2 * SIGNATURE_ALGORITHMS[alg]:
        raise IntegrityError(f"Malformed signature {value!r}: wrong length")
    return alg, bytes.fromhex(hex_part)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise IntegrityError("Invalid log line: duplicate JSON key")
    return obj


def _reject_number(value: str) -> NoReturn:
    raise IntegrityError(f"Invalid log line: non-integer number {value!r}")


def parse_line(line: str) -> dict[str, Any]:
    """Parse one NDJSON log line under the strict rules of the module docstring.

    Raises:
        IntegrityError: malformed JSON, duplicate keys, floats or NaN/Infinity.
    """
    try:
        obj = json.loads(
            line,
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except json.JSONDecodeError as exc:
        raise IntegrityError(f"Invalid log line: {exc.msg}") from None
    if not isinstance(obj, dict):
        raise IntegrityError("Invalid log line: not a JSON object")
    return obj
