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
* Relation to RFC 8785 (JSON Canonicalization Scheme, owner decision D18):
  the format specifies canonical bytes as RFC 8785 *restricted* to ASCII
  object keys and integers in [-(2^53-1), 2^53-1] (``MAX_SAFE_INTEGER``).
  Inside that subset ``json.dumps`` above is byte-identical to JCS (same
  string escaping, keys sorted by code point = by UTF-16 code unit for
  ASCII).  We deliberately do NOT implement RFC 8785 in its broadest form:
  JCS sorts non-ASCII keys by UTF-16 code units (Python sorts by code point,
  which differs for characters outside the BMP) and serialises every number
  as an IEEE-754 double (ECMAScript ``Number.prototype.toString``), while we
  allow integers only.  Writers (:func:`canonical_bytes`) and readers
  (:func:`parse_line`) therefore reject numbers outside the subset.  Any
  future enhancement (non-ASCII keys, floats, larger integers) must either
  switch to a full JCS implementation or extend the restriction knowingly;
  see the backlog item CLIPYPI:RFC8785-FULL.
* Algorithm agility: every digest is written ``<hash_alg>:<lowercase hex>``
  (e.g. ``sha256:…``) and every signature ``<sig_alg>:<lowercase hex>`` (e.g.
  ``ed25519:…``).  An event names its algorithms in ``header.hash_alg`` and
  ``header.sig_alg``; its ``prev_hash`` and ``signature`` prefixes must match.
* Event hash: digest, under a given ``hash_alg``, of the canonical bytes of
  the whole event (``header``, ``body`` and ``signature``).  The next event's
  ``header.prev_hash`` holds it, computed with *that* event's ``hash_alg``.
* Log lines are parsed strictly: bytes that are not UTF-8, duplicate object
  keys, floats, the non-standard constants ``NaN``/``Infinity`` and integers
  outside the canonical range make a line invalid, because implementations
  disagree on how to read or re-serialise them.  A string holding a lone
  surrogate (``"\\ud800"``) is not a Unicode scalar value and has no UTF-8
  encoding: its canonical bytes do not exist (``IntegrityError``)."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from typing import Any, NoReturn

from pydantic import BaseModel

from indiek.core.errors import ArchiveRuleError, IntegrityError

DEFAULT_HASH_ALG = "sha256"
DEFAULT_SIG_ALG = "ed25519"

# Supported algorithms: hash name -> constructor; signature name -> byte length.
HASH_ALGORITHMS: dict[str, Callable[[bytes], Any]] = {"sha256": hashlib.sha256}
SIGNATURE_ALGORITHMS: dict[str, int] = {"ed25519": 64}

_LOWER_HEX = re.compile(r"[0-9a-f]*")

# Largest integer an IEEE-754 double holds exactly (RFC 8785 / I-JSON safe range).
MAX_SAFE_INTEGER = 2**53 - 1
_MAX_SAFE_DIGITS = len(str(MAX_SAFE_INTEGER))


def json_ready(obj: Mapping[str, Any] | BaseModel) -> dict[str, Any]:
    """Plain JSON-compatible ``dict`` of a mapping or a pydantic model."""
    if isinstance(obj, BaseModel):
        return obj.model_dump(mode="json")
    return dict(obj)


def _check_numbers(value: Any) -> None:
    """Refuse numbers outside the canonical subset (D18): floats, and integers
    beyond ``MAX_SAFE_INTEGER`` in absolute value."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, bool) or item is None or isinstance(item, str):
            continue
        if isinstance(item, int):
            if not -MAX_SAFE_INTEGER <= item <= MAX_SAFE_INTEGER:
                raise ArchiveRuleError(
                    f"Integer {item} is outside the canonical range ±(2^53−1)"
                )
        elif isinstance(item, float):
            raise ArchiveRuleError(f"Non-integer number {item!r} cannot be written")
        elif isinstance(item, Mapping):
            stack.extend(item.values())
        elif isinstance(item, (list, tuple)):
            stack.extend(item)


def canonical_bytes(obj: Mapping[str, Any] | BaseModel) -> bytes:
    """Return the canonical bytes of ``obj`` (see the module docstring).

    Raises:
        ArchiveRuleError: ``obj`` holds a float or an integer outside
            ±(2^53−1) (only a writer can produce one; readers reject such
            lines in :func:`parse_line`).
        IntegrityError: ``"Invalid string: lone surrogate …"``.
    """
    ready = json_ready(obj)
    _check_numbers(ready)
    text = json.dumps(ready, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError:
        raise IntegrityError(
            "Invalid string: lone surrogate (not a Unicode scalar value)"
        ) from None


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


def _parse_int(value: str) -> int:
    # Checked on the digits first: int() of a 5,000-digit literal raises ValueError.
    if len(value.lstrip("-")) > _MAX_SAFE_DIGITS or abs(int(value)) > MAX_SAFE_INTEGER:
        raise IntegrityError(
            f"Invalid log line: integer {value[:20]}{'…' if len(value) > 20 else ''} "
            "is outside ±(2^53−1)"
        )
    return int(value)


def parse_line(line: str | bytes) -> dict[str, Any]:
    """Parse one NDJSON log line under the strict rules of the module docstring.

    Raises:
        IntegrityError: bytes that are not UTF-8, malformed JSON, duplicate
            keys, floats, NaN/Infinity or integers outside ±(2^53−1).
    """
    if isinstance(line, bytes):
        try:
            line = line.decode("utf-8")
        except UnicodeDecodeError:
            raise IntegrityError("Invalid log line: not UTF-8") from None
    try:
        obj = json.loads(
            line,
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=_reject_number,
            parse_int=_parse_int,
            parse_constant=_reject_number,
        )
    except json.JSONDecodeError as exc:
        raise IntegrityError(f"Invalid log line: {exc.msg}") from None
    if not isinstance(obj, dict):
        raise IntegrityError("Invalid log line: not a JSON object")
    return obj
