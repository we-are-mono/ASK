"""Artifact paths shared by fixtures, transports, and pytest reporting."""

import hashlib
import json
import os
import re
from pathlib import Path


def artifact_dir(nodeid=None):
    root = Path(os.environ.get("ASK_TEST_RUN_DIR", "/tmp/ask-tests/unmanaged"))
    if nodeid is None:
        current = os.environ.get("PYTEST_CURRENT_TEST", "session")
        nodeid = current.rsplit(" (", 1)[0]
    name = re.sub(r"[^a-zA-Z0-9_.-]+", "_", nodeid)[:140]
    digest = hashlib.sha256(nodeid.encode()).hexdigest()[:12]
    path = root / f"{name}-{digest}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def record(name, data, *, nodeid=None):
    path = artifact_dir(nodeid) / f"{name}.json"
    path.write_text(json.dumps(data, indent=2, default=str) + "\n")
    return path
