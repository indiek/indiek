"""SDK2:WRITE-LOCK: one writer at a time per archive, across processes.

Owner decisions 2026-10-25: the ``filelock`` package; the lock file is
``<archive>/.ik.lock`` (ignored by every reader); a writer waits up to
``lock_timeout`` seconds (default 10) and then raises ``ArchiveLockedError``.
Inside the lock every write first re-reads the archive, so it chains onto the
true head even when another process (Desktop App, ``ik``) wrote in between.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

import indiek
from indiek import Archive, ArchiveLockedError, IndieKError
from indiek.core.author import Author
from indiek.ops import ingest as ingest_ops
from indiek.ops import seal as seal_ops

SEED = "78" * 32  # public test vector, not a secret
AUTHOR = Author.from_seed_hex(SEED)
LOCK_NAME = ".ik.lock"


def _python(code: str, *args: str, **kwargs: Any) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [sys.executable, "-c", textwrap.dedent(code), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        text=True,
        **kwargs,
    )


@contextmanager
def _lock_held_elsewhere(
    root: Path, *, release_after: float | None = None
) -> Iterator[None]:
    """Hold ``<root>/.ik.lock`` from another process (until the block ends, or
    for ``release_after`` seconds)."""
    holder = _python(
        """
        import sys, time
        from filelock import FileLock
        lock = FileLock(sys.argv[1])
        with lock:
            print("locked", flush=True)
            if sys.argv[2] == "stdin":
                sys.stdin.read()
            else:
                time.sleep(float(sys.argv[2]))
        """,
        str(root / LOCK_NAME),
        "stdin" if release_after is None else str(release_after),
    )
    try:
        assert holder.stdout is not None
        assert holder.stdout.readline().strip() == "locked"
        yield
    finally:
        if holder.stdin is not None:
            holder.stdin.close()
        holder.wait(timeout=30)


def _lock_is_held(root: Path) -> bool:
    """Probe the lock from another process without waiting."""
    probe = _python(
        """
        import sys
        from filelock import FileLock, Timeout
        try:
            with FileLock(sys.argv[1], timeout=0):
                print("free")
        except Timeout:
            print("held")
        """,
        str(root / LOCK_NAME),
    )
    out, err = probe.communicate(timeout=30)
    assert probe.returncode == 0, err
    return out.strip() == "held"


def _full_count(root: Path) -> int:
    return Archive.open(root, verify="full").fsck().base_count


# -- the error -------------------------------------------------------------


def test_archive_locked_error_is_exported_and_an_indiek_error() -> None:
    assert indiek.ArchiveLockedError is ArchiveLockedError
    assert issubclass(ArchiveLockedError, IndieKError)
    assert "ArchiveLockedError" in indiek.__all__


# -- stale handles ---------------------------------------------------------


def test_stale_handles_chain_onto_the_true_head(archive_root: Path) -> None:
    first = Archive.open(archive_root, author=AUTHOR)
    second = Archive.open(archive_root, author=AUTHOR)  # opened before `first` writes
    first.create_node("one")
    second.create_node("two")  # used to fork the log: "Chain broken!"
    first.create_node("three")
    assert _full_count(archive_root) == 3


def test_stale_handle_sees_items_written_by_others(archive_root: Path) -> None:
    writer = Archive.open(archive_root, author=AUTHOR)
    stale = Archive.open(archive_root, author=AUTHOR)
    source = writer.create_node("source")
    target = writer.create_node("target")
    stale.create_edge(source, target, "links")  # validated against the fresh state
    tag = stale.create_tag("claim", "A claim", kind="node")
    writer.set_tag(tag, source)
    assert _full_count(archive_root) == 3
    assert writer.index.meta_head == Archive.open(archive_root).meta_head


# -- processes -------------------------------------------------------------


def test_concurrent_processes_keep_one_valid_chain(archive_root: Path) -> None:
    per_process = 12
    writers = [
        _python(
            """
            import sys
            from indiek import Archive, Author
            ik = Archive.open(sys.argv[1], author=Author.from_seed_hex(sys.argv[2]))
            for i in range(int(sys.argv[3])):
                ik.create_node(f"{sys.argv[4]}-{i}")
            """,
            str(archive_root),
            SEED,
            str(per_process),
            name,
        )
        for name in ("app", "cli")
    ]
    for writer in writers:
        _, err = writer.communicate(timeout=120)
        assert writer.returncode == 0, err
    assert _full_count(archive_root) == 2 * per_process


def test_a_writer_waits_for_a_short_lock(archive_root: Path) -> None:
    ik = Archive.open(archive_root, author=AUTHOR)
    with _lock_held_elsewhere(archive_root, release_after=0.5):
        ik.create_node("after the wait")
    assert _full_count(archive_root) == 1


def test_a_writer_gives_up_after_lock_timeout(
    archive_root: Path, base_events: Callable[[], list[dict[str, Any]]]
) -> None:
    ik = Archive.open(archive_root, author=AUTHOR, lock_timeout=0.3)
    with _lock_held_elsewhere(archive_root):
        with pytest.raises(
            ArchiveLockedError, match="being written by another process"
        ):
            ik.create_node("blocked")
    assert base_events() == []
    ik.create_node("now free")
    assert _full_count(archive_root) == 1


def test_lock_timeout_must_not_be_negative(archive_root: Path) -> None:
    with pytest.raises(ValueError, match="lock_timeout"):
        Archive.open(archive_root, author=AUTHOR, lock_timeout=-1)


@pytest.mark.parametrize("operation", ["create_node", "seal", "ingest"])
def test_writes_hold_the_lock_while_appending(
    archive_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    ik = Archive.open(archive_root, author=AUTHOR)
    ik.create_node("seed")
    held: list[bool] = []

    def probing(original: Callable[..., Any]) -> Callable[..., Any]:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            held.append(_lock_is_held(archive_root))
            return original(*args, **kwargs)

        return wrapper

    if operation == "create_node":
        from indiek.ops import nodes

        monkeypatch.setattr(
            nodes, "create_managed_node", probing(nodes.create_managed_node)
        )
        ik.create_node("probed")
    elif operation == "seal":
        monkeypatch.setattr(seal_ops, "seal", probing(seal_ops.seal))
        ik.seal()
    else:
        monkeypatch.setattr(ingest_ops, "ingest", probing(ingest_ops.ingest))
        folder = tmp_path / "to-ingest"
        folder.mkdir()
        (folder / "note.md").write_text("# Note\n", encoding="utf-8")
        ik.ingest(input_folder=folder)
    assert held == [True]
    assert not _lock_is_held(archive_root)


# -- readers ignore the lock file -----------------------------------------


def test_lock_file_is_ignored_by_every_reader(archive_root: Path) -> None:
    ik = Archive.open(archive_root, author=AUTHOR)
    ik.create_node("one")
    (archive_root / LOCK_NAME).touch()  # left behind, whatever the platform does
    reopened = Archive.open(archive_root, author=AUTHOR, verify="full")
    report = reopened.fsck()
    assert report.unreferenced_blobs == []
    assert reopened.verify() is None
    reopened.write_manifest()
    reopened.seal()
    reopened.create_node("two")
    assert _full_count(archive_root) == 2


def test_writing_to_a_missing_folder_still_creates_the_archive(tmp_path: Path) -> None:
    root = tmp_path / "new" / "archive"
    Archive.open(root, author=AUTHOR).create_node("first")
    assert _full_count(root) == 1


def test_read_only_operations_never_take_the_lock(archive_root: Path) -> None:
    Archive.open(archive_root, author=AUTHOR).create_node("one")
    with _lock_held_elsewhere(archive_root):
        reader = Archive.open(archive_root, author=AUTHOR, lock_timeout=0)
        reader.verify()
        reader.fsck()
        assert len(list(reader.events())) == 1
