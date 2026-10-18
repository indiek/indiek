"""Every ``python`` code block of README.md runs, in order, in one namespace.

The README's SDK examples are a single story (quickstart, then the reference
sections build on its ``ik``, ``theorem``, ``seal`` …), so they are executed
top to bottom inside a temporary working directory holding the sample files
they mention.  A block that stops working fails this test.  Blocks fenced
``py`` (signatures, not runnable code) are not executed.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

README = Path(__file__).resolve().parents[2] / "README.md"
PYTHON_BLOCK = re.compile(r"^```python\n(.*?)^```$", re.MULTILINE | re.DOTALL)


def _blocks() -> list[str]:
    return PYTHON_BLOCK.findall(README.read_text(encoding="utf-8"))


@pytest.fixture
def workdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The sample files the README examples read, in a fresh working directory."""
    (tmp_path / "figures").mkdir()
    (tmp_path / "figures" / "diagram.png").write_bytes(b"\x89PNG\r\n\x1a\n" + bytes(8))
    (tmp_path / "scans").mkdir()
    (tmp_path / "scans" / "page.tiff").write_bytes(b"II*\x00" + bytes(8))
    (tmp_path / "more").mkdir()
    (tmp_path / "more" / "cites.txt").write_text("A citing note.", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_the_readme_has_python_examples() -> None:
    assert len(_blocks()) >= 10


def test_every_readme_python_block_runs(workdir: Path) -> None:
    namespace: dict[str, object] = {"__name__": "readme"}
    for number, block in enumerate(_blocks(), start=1):
        try:
            exec(compile(block, f"README.md python block {number}", "exec"), namespace)
        except Exception as exc:  # pragma: no cover - reported with the block
            pytest.fail(f"README python block {number} failed: {exc!r}\n{block}")
    assert (workdir / "my-archive" / "SPEC.md").is_file()
