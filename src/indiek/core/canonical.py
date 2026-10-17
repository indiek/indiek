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

Canonical serialisation, event hashes and strict parsing of log lines
(format 3.0).

* Canonical bytes: ``json.dumps(obj, sort_keys=True, separators=(",", ":"),
  ensure_ascii=False)`` encoded as UTF-8.  Pydantic models are first dumped
  with ``model_dump(mode="json")``.
* Event hash: lowercase hex SHA-256 of the canonical bytes of the whole event
  (``header``, ``body`` and ``signature``).  The next event's
  ``header.prev_hash`` holds it.
* Log lines are parsed strictly: duplicate object keys, floats and the
  non-standard constants ``NaN``/``Infinity`` make a line invalid, because
  implementations disagree on how to read or re-serialise them."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any, NoReturn

from pydantic import BaseModel

from indiek.core.errors import IntegrityError


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


def event_hash(event: Mapping[str, Any] | BaseModel) -> str:
    """Lowercase hex SHA-256 of the canonical bytes of the whole event."""
    return hashlib.sha256(canonical_bytes(event)).hexdigest()


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
