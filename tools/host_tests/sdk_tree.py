"""Each kernel line's NXP SDK copy (sdk/<line>) is what replaces mainline.

The kernel recipe overlays the paths NXP_SDK_PATHS names from the line's copy
before the series applies. A listed path the copy lacks fails the build; a
file outside the listed paths would sit in the checkout and in the kernel
record, yet never reach a kernel tree; and a patch touching a listed path
would make the copy no longer the one place the SDK's code is read from.
"""

import pytest

import kernel_series
from ask_orch import kernel_line


@pytest.mark.parametrize("name", kernel_line.lines())
def test_each_lines_sdk_copy_holds_exactly_the_overlaid_paths(name):
    line = kernel_series.Line(name)
    tree = line.sdk
    assert tree.is_dir(), f"{tree} does not exist"
    missing = [entry for entry in line.overlay if not (tree / entry).exists()]
    stray = sorted(str(path.relative_to(tree)) for path in tree.rglob("*")
                   if path.is_file() and not line.in_sdk(str(path.relative_to(tree))))
    assert not missing, f"NXP_SDK_PATHS entries not in {tree}: {missing}"
    assert not stray, f"files in {tree} outside NXP_SDK_PATHS: {stray}"


@pytest.mark.parametrize("name", kernel_line.lines())
def test_no_patch_touches_the_sdk_copy(name):
    assert not kernel_series.sdk_patches(kernel_series.Line(name)), (
        f"patches change sdk/{name} files (count each), which are edited in place instead")
