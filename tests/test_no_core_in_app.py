"""Guard the Phase-2 decoupling.

Streamlit (`app.py`) must remain a pure HTTP client of the API — no
direct imports of the agent's internal state, repositories, or core
services. The CI runs this test so a future refactor can't silently
re-couple them.
"""

from __future__ import annotations

from pathlib import Path

import pytest


APP_PY = Path(__file__).parent.parent / "app.py"


FORBIDDEN_IMPORTS = [
    "from segmentation_copilot import tools",
    "from segmentation_copilot.tools",
    "import segmentation_copilot.tools",
    "from segmentation_copilot.core",
    "import segmentation_copilot.core",
    "from segmentation_copilot import db",
    "from segmentation_copilot.db",
]


def test_app_does_not_import_internal_modules() -> None:
    """app.py must talk to the API, not the agent core directly."""
    assert APP_PY.exists(), f"expected {APP_PY} to exist"
    source = APP_PY.read_text(encoding="utf-8")
    offenders = [line for line in FORBIDDEN_IMPORTS if line in source]
    assert not offenders, (
        f"app.py reaches into internal modules: {offenders}. "
        "It must remain a pure HTTP client of the FastAPI service."
    )
