"""CLI-only fixtures for the ``ik`` command-line tests.

Kept out of the root ``conftest.py`` so that the SDK suite (``tests/sdk/``)
never imports ``indiek.cli`` and therefore never pulls in ``dotenv`` or
``rich``.  Archive, author and log-reading fixtures are inherited from the
root ``conftest.py``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

import pytest

from indiek import cli as ik_cli


@pytest.fixture
def run_cli(
    archive_root: Path,
    author_seed_hex: str,
    monkeypatch: pytest.MonkeyPatch,
) -> Callable[..., None]:
    """Invoke ``indiek.cli.main()`` as if from the shell, against ``archive_root``.

    ``--dot-env`` is pointed at a non-existent file so that ``load_dotenv`` is a
    no-op and only the environment set here is visible.  ``seed_hex`` lets a
    single test act as a different author.
    """

    empty_dotenv = archive_root.parent / "absent.env"

    def _run(*argv: str, seed_hex: str | None = None) -> None:
        monkeypatch.setenv("IK_ARCHIVE_PATH", str(archive_root))
        monkeypatch.setenv("IK_AUTHOR_PRIVATE_KEY", seed_hex or author_seed_hex)
        monkeypatch.setattr(
            "sys.argv",
            [
                "ik",
                "--dot-env",
                str(empty_dotenv),
                "--logging-level",
                "CRITICAL",
                *argv,
            ],
        )
        ik_cli.main()

    return _run
