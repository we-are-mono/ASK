"""Load the common ASK runner hooks and pytest's harness-testing support."""
import os
from pathlib import Path

import pytest

# Fixture modules are loaded by pytest, but are not test modules themselves.
collect_ignore_glob = ["**/conftest.py"]

# Helpers keep pytest's detailed assertion messages after leaving test modules.
pytest.register_assert_rewrite("ask_orch", *(
    path.stem for suite in ("tests", "host_tests")
    for path in (Path(__file__).parent / suite).glob("_*.py")
    if path.stem != "__init__"
))

pytest_plugins = ["ask_orch.pytest_plugin", "pytester"]


@pytest.fixture
def pytester(pytester, monkeypatch):
    """A nested session imports the runner as this one does. The ini's
    pythonpath reaches only this process, so a subprocess run is given the
    tools directory as `make test-host` gives it, however pytest was started."""
    inherited = os.environ.get("PYTHONPATH")
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join(
        [str(Path(__file__).parent)] + ([inherited] if inherited else [])))
    return pytester
