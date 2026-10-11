"""A component's build record: the checkout files a recipe built from.

meta-ask/classes-recipe/ask-provenance.bbclass loads this file by path inside
bitbake, so it uses the standard library only and works on any Python bitbake
supports. Everything here is part of what a record means: a change rebuilds
every recipe, so the harness's other code lives in ask_orch.manifest.
"""

import hashlib
import json
import os
from pathlib import Path
import subprocess

TREE_FILE = ".ask-provenance.json"


def names(root, paths=()):
    """Checkout-relative names of the files git would commit under `paths`,
    or in the whole checkout when none are given: tracked or not, never
    ignored. Only the checkout's own ignore rules count: kas gives bitbake a
    home of its own, so a user's global excludes would make the build and the
    harness disagree."""
    output = subprocess.check_output(
        ["git", "-c", "core.excludesFile=/dev/null", "ls-files", "-z", "--cached", "--others",
         "--exclude-standard", "--", *paths], cwd=root, timeout=30)
    return sorted({os.fsdecode(name) for name in output.split(b"\0") if name})


def files(root, paths):
    """Each file under `paths` by the digest of its content, as the build
    reads it: through links, without its mode, and only if it exists. No
    paths name no files, not the whole checkout."""
    if not paths:
        return {}
    result = {}
    for name in names(root, paths):
        path = Path(root) / name
        if path.is_file():
            result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def record(root, component, paths):
    """The record of `component` built from `paths`. A path inside another
    listed directory adds nothing, so it is left out."""
    paths = set(paths)
    kept = sorted(path for path in paths
                  if not any(path.startswith(other.rstrip("/") + "/") for other in paths))
    return {"component": component, "paths": kept, "files": files(root, kept)}


def encode(entry):
    return json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
