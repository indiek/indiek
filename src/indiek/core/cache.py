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

The local verification cache: what THIS machine already verified.

Owner decisions 2026-10-17 (CLIPYPI:VERIFY-LEVELS-CACHE): the cache lives
OUTSIDE the archive, in the user's cache directory, so nothing shipped with an
archive can make a reader skip checks.  It is non-authoritative and
regenerable: deleting it only costs time.

Content (D14), per archive::

    {"format": 1, "archive": "<abs path>",
     "logs": {"base": {"count": N, "head": "sha256:…"}, "meta": {…}},
     "blobs": {"<digest>": [size, mtime_ns], …}}

``logs.<log>`` means "the signatures of events 1..count were verified and
event #count hashed to head".  A reader recomputes the hash chain anyway, so
a stale or corrupted entry is simply not confirmed and the log is fully
checked.  ``blobs`` lists files already re-hashed, keyed by size and
modification time (blind spot: rot that keeps both; see verify-on-read).

This module never reads the process environment: the facade passes it in."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

CACHE_DIR_VAR = "IK_CACHE_DIR"
CACHE_FORMAT = 1


def default_cache_dir(*, environ: Mapping[str, str], platform: str, home: Path) -> Path:
    """The user's cache directory for IndieK, following platform conventions.

    ``IK_CACHE_DIR`` wins; then macOS ``~/Library/Caches/indiek``, Windows
    ``%LOCALAPPDATA%\\indiek\\Cache``, otherwise XDG
    ``$XDG_CACHE_HOME/indiek`` (default ``~/.cache/indiek``).
    """
    if override := environ.get(CACHE_DIR_VAR):
        return Path(override)
    if platform == "darwin":
        return home / "Library" / "Caches" / "indiek"
    if platform.startswith("win"):
        local = environ.get("LOCALAPPDATA")
        return (
            (Path(local) if local else home / "AppData" / "Local") / "indiek" / "Cache"
        )
    xdg = environ.get("XDG_CACHE_HOME")
    return (Path(xdg) if xdg else home / ".cache") / "indiek"


def cache_path(cache_dir: Path, archive_root: Path) -> Path:
    """Cache file of one archive, keyed by a hash of its resolved path."""
    resolved = str(Path(archive_root).expanduser().resolve())
    key = hashlib.sha256(resolved.encode("utf-8")).hexdigest()[:32]
    return Path(cache_dir) / key / "state.json"


@dataclass(frozen=True, slots=True)
class VerifiedTip:
    """Events 1..``count`` of a log had valid signatures; #``count`` hashed to ``head``."""

    count: int
    head: str


@dataclass(slots=True)
class VerificationCache:
    base: VerifiedTip | None = None
    meta: VerifiedTip | None = None
    blobs: dict[str, tuple[int, int]] = field(default_factory=dict)


def _tip(raw: Any) -> VerifiedTip | None:
    if not isinstance(raw, dict):
        return None
    count, head = raw.get("count"), raw.get("head")
    if type(count) is int and count > 0 and isinstance(head, str):
        return VerifiedTip(count, head)
    return None


def load_cache(cache_dir: Path, archive_root: Path) -> VerificationCache:
    """The cached state of ``archive_root``; empty if absent or unreadable."""
    try:
        data = json.loads(cache_path(cache_dir, archive_root).read_text("utf-8"))
        logs, blobs = data["logs"], data["blobs"]
        if data.get("format") != CACHE_FORMAT or not isinstance(blobs, dict):
            return VerificationCache()
        return VerificationCache(
            base=_tip(logs.get("base")),
            meta=_tip(logs.get("meta")),
            blobs={
                str(k): (int(v[0]), int(v[1]))
                for k, v in blobs.items()
                if isinstance(v, list) and len(v) == 2
            },
        )
    except OSError, ValueError, TypeError, KeyError, AttributeError:
        return VerificationCache()


def save_cache(cache_dir: Path, archive_root: Path, cache: VerificationCache) -> None:
    """Atomically write the cache; failures (e.g. read-only home) are ignored."""
    path = cache_path(cache_dir, archive_root)
    data = {
        "format": CACHE_FORMAT,
        "archive": str(Path(archive_root).expanduser().resolve()),
        "logs": {
            name: {"count": tip.count, "head": tip.head}
            for name, tip in (("base", cache.base), ("meta", cache.meta))
            if tip is not None
        },
        "blobs": {k: list(v) for k, v in sorted(cache.blobs.items())},
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".state-", suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        os.replace(tmp, path)
    except OSError as exc:
        logger.debug("Verification cache not written to %s: %s", path, exc)
