"""The SDK must not pull in CLI-only dependencies (``rich``, ``dotenv``)."""

from __future__ import annotations

import subprocess
import sys


def test_importing_the_sdk_loads_no_cli_dependencies() -> None:
    code = (
        "import sys, indiek, indiek.sdk, indiek.core, indiek.ops;"
        "print(sorted(m for m in ('rich', 'dotenv') if m in sys.modules))"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == "[]"
