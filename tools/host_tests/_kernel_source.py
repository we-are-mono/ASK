"""The patched kernel tree the host tests compile from.

The image build unpacks it, and it follows patches/kernel/ only once a build
has run since the series changed. Compiling from an older tree would test the
old patches and pass on them, so the tree must carry the record of the inputs
it was prepared from (ask_orch.manifest), and they must be this checkout's.
"""

import functools
import os
from pathlib import Path

import pytest

from ask_orch import manifest

ROOT = Path(__file__).resolve().parents[2]
DEFAULT = ROOT / "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"


@functools.cache
def _problem(path):
    if not path.is_dir():
        return f"{path} does not exist"
    return manifest.tree(ROOT, path, manifest.KERNEL)


def kernel_source():
    """The image build's kernel tree, or ASK_KERNEL_SOURCE's: either way one
    an image build of this checkout prepared."""
    path = Path(os.environ.get("ASK_KERNEL_SOURCE", DEFAULT))
    if problem := _problem(path):
        pytest.fail(f"{problem}; build the image from this checkout (make ask-image), "
                    "or point ASK_KERNEL_SOURCE at a kernel tree such a build prepared")
    return path
