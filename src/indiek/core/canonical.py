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

Canonical serialisation of events and bodies (format 2.0).

Format 2.0 rule: ``json.dumps(obj, sort_keys=True)`` with Python's default
separators (``", "`` and ``": "``) and ``ensure_ascii=True``, encoded as UTF-8.
Pydantic models are first dumped with ``model_dump(mode="json")``."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel


def _as_json_ready(obj: Mapping[str, Any] | BaseModel) -> Any:
    if isinstance(obj, BaseModel):
        return obj.model_dump(mode="json")
    return obj


def canonical_bytes(obj: Mapping[str, Any] | BaseModel) -> bytes:
    """Return the bytes that are hashed and signed for ``obj``."""
    return json.dumps(_as_json_ready(obj), sort_keys=True).encode("utf-8")


def canonical_hash(obj: Mapping[str, Any] | BaseModel) -> bytes:
    """Return the raw SHA-256 digest of :func:`canonical_bytes`."""
    return hashlib.sha256(canonical_bytes(obj)).digest()
