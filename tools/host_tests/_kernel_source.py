"""The patched kernel tree the host tests compile from.

The image build unpacks it, and it follows the line's patch series
(patches/kernel/<line>) only once a build has run since the series changed.
Compiling from an older tree would test the old patches and pass on them, so
the tree must carry the record of the inputs it was prepared from
(ask_orch.manifest), and they must be this checkout's, for the line ASK_LINE
names.
"""

import functools
import os
from pathlib import Path

import pytest

from ask_orch import kernel_line, manifest

ROOT = Path(__file__).resolve().parents[2]


@functools.cache
def _problem(path, line):
    if not path.is_dir():
        return f"{path} does not exist"
    return manifest.tree(ROOT, path, manifest.KERNEL, line)


def kernel_source():
    """The image build's kernel tree for the line, or ASK_KERNEL_SOURCE's:
    either way one an image build of this checkout prepared for it."""
    line = kernel_line.current()
    path = Path(os.environ.get("ASK_KERNEL_SOURCE") or kernel_line.kernel_source(line))
    if problem := _problem(path, line):
        pytest.fail(f"{problem}; build the image from this checkout (make ask-image LINE={line}), "
                    "or point ASK_KERNEL_SOURCE at a kernel tree such a build prepared")
    return path
