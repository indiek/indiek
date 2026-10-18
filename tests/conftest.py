"""Shared fixtures for the IndieK test-suite (SDK and CLI).

Every test runs against a throwaway archive created under pytest's ``tmp_path``
(the OS temp directory), never inside the repository, and signs with an
ephemeral Ed25519 seed generated in-process.  That seed is a test artefact, not
a secret: it is never written to a dotenv in the repo and grants no authority
over any real archive.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Iterator

import nacl.encoding
import nacl.signing
import pytest


def _generate_author() -> tuple[str, str]:
    """Return an ephemeral ``(seed_hex, public_key_hex)`` Ed25519 pair."""
    signing_key = nacl.signing.SigningKey.generate()
    seed_hex = signing_key.encode(nacl.encoding.HexEncoder).decode("utf-8")
    public_key_hex = signing_key.verify_key.encode(nacl.encoding.HexEncoder).decode(
        "utf-8"
    )
    return seed_hex, public_key_hex


@pytest.fixture(scope="session")
def author() -> tuple[str, str]:
    """The default test author, stable for the whole session."""
    return _generate_author()


@pytest.fixture(scope="session")
def author_seed_hex(author: tuple[str, str]) -> str:
    return author[0]


@pytest.fixture(scope="session")
def author_public_key(author: tuple[str, str]) -> str:
    return author[1]


@pytest.fixture(scope="session")
def other_author() -> tuple[str, str]:
    """A second author, used to exercise tag-authorship rejection."""
    return _generate_author()


@pytest.fixture
def archive_root(tmp_path: Path) -> Path:
    """An empty archive root inside the OS temp directory."""
    root = tmp_path / "archive"
    root.mkdir()
    return root


def _read_ndjson(log_root: Path) -> list[dict[str, Any]]:
    """Read every event under ``log_root/events`` in canonical log order."""
    paths = sorted(str(path) for path in (log_root / "events").rglob("*ndjson"))
    events: list[dict[str, Any]] = []
    for path in paths:
        with open(path, "rt", encoding="utf-8") as handle:
            events.extend(json.loads(line) for line in handle)
    return events


@pytest.fixture
def base_events(archive_root: Path) -> Callable[[], list[dict[str, Any]]]:
    """Callable returning the base-network event log as parsed dicts."""
    return lambda: _read_ndjson(archive_root)


@pytest.fixture
def meta_events(archive_root: Path) -> Callable[[], list[dict[str, Any]]]:
    """Callable returning the meta-network event log as parsed dicts."""
    return lambda: _read_ndjson(archive_root / "meta")


@pytest.fixture
def blob_paths(archive_root: Path) -> Callable[[], list[Path]]:
    """Callable returning every blob file currently in the blob store."""
    blobs = archive_root / "blobs" / "sha256"
    return lambda: sorted(path for path in blobs.rglob("*") if path.is_file())


@pytest.fixture
def sample_files(tmp_path: Path) -> dict[str, Path]:
    """A handful of on-disk files with supported and unsupported extensions."""
    directory = tmp_path / "inputs"
    directory.mkdir()
    markdown = directory / "limits.md"
    markdown.write_text("# Limits\n\nA note about limits.\n", encoding="utf-8")
    plain = directory / "note.txt"
    plain.write_text("plain text body", encoding="utf-8")
    png = directory / "scan.png"
    png.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 16)
    unsupported = directory / "data.csv"
    unsupported.write_text("a,b\n1,2\n", encoding="utf-8")
    return {
        "markdown": markdown,
        "plain": plain,
        "png": png,
        "unsupported": unsupported,
    }


@pytest.fixture(autouse=True)
def _quiet_logging() -> Iterator[None]:
    """Keep the root logger from accumulating handlers across CLI invocations."""
    import logging

    root = logging.getLogger()
    original_handlers = list(root.handlers)
    original_level = root.level
    yield
    root.handlers = original_handlers
    root.setLevel(original_level)


@pytest.fixture(autouse=True)
def ik_cache_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the verification cache (``IK_CACHE_DIR``) into this test's tmp dir,
    so no test reads or writes the user's real cache."""
    cache = tmp_path / "ik-cache"
    monkeypatch.setenv("IK_CACHE_DIR", str(cache))
    return cache
