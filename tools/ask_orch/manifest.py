"""The build manifest: whether a DUT image, or a source tree the image build
unpacked, was built from this checkout.

Every recipe in meta-ask records the checkout files it builds from before it
reads them (meta-ask/classes-recipe/ask-provenance.bbclass and
ask_orch.build_record), and the image carries the records. A record is
canonical JSON, so the image, the unpacked trees and the checkout all compare
by its bytes.
"""

import hashlib
import json
from pathlib import Path

from ask_orch.build_record import TREE_FILE, encode, record

# Where the image carries its records.
IMAGE_DIR = "/usr/share/ask/provenance"
# U-Boot loads the device tree apart from the kernel. The test image's tree
# carries this root property, the digest of the kernel record of the build
# that compiled it, so a tree from another build is told apart.
DEVICETREE_PROPERTY = "mono,ask-provenance"
KERNEL = "linux-ask"
REMEDY = "rebuild with make ask-image, run make stage-image and boot the staged image"
# Where the image build leaves each recipe's record.
BUILD_RECORDS = "meta-ask/build/tmp/work/*/{0}/*/ask-provenance/{0}.json"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def components(root):
    """What an image built from this checkout records: one component per
    recipe in the layer, named as bitbake names it."""
    return sorted(path.name.split("_")[0].removesuffix(".bb")
                  for path in (Path(root) / "meta-ask").glob("recipes-*/*/*.bb"))


def _difference(root, name, entry):
    """Which files changed since the DUT's record, when the image build still
    holds it; otherwise only that the build tree did not last build it."""
    for path in Path(root).glob(BUILD_RECORDS.format(name)):
        data = path.read_bytes()
        if digest(data) == entry["sha256"]:
            then, now = json.loads(data), record(root, name, entry["paths"])
            changed = sorted(n for n in then["files"].keys() | now["files"].keys()
                             if then["files"].get(n) != now["files"].get(n))
            if not changed:
                return "its record lists other inputs"
            return "; ".join(changed[:5]) + (f" and {len(changed) - 5} more" if len(changed) > 5 else "")
    return "not what this build tree last built"


def verify(root, image):
    """How a DUT image differs from one built from this checkout, one line
    per difference; empty when it matches. `image` is the DUT's report: each
    record's digest and inputs, and its device tree's property."""
    build = image.get("build") or {}
    expected = components(root)
    problems = []
    for name in expected:
        entry = build.get(name)
        if entry is None:
            problems.append(f"{name}: the image carries no record of it")
        elif not isinstance(entry.get("paths"), list):
            problems.append(f"{name}: the image's record of it is unreadable")
        elif digest(encode(record(root, name, entry["paths"]))) != entry["sha256"]:
            problems.append(f"{name}: built from other sources than this checkout's "
                            f"({_difference(root, name, entry)})")
    problems += [f"{name}: no recipe in this checkout builds it"
                 for name in sorted(build.keys() - set(expected))]
    kernel = build.get(KERNEL)
    if kernel and image.get("devicetree") != kernel["sha256"]:
        problems.append("device tree: " + ("compiled by another kernel build" if image.get("devicetree")
                                           else f"carries no {DEVICETREE_PROPERTY}"))
    return problems


def tree(root, path, component):
    """Why a source tree the build unpacked for `component` was not made from
    this checkout's inputs, or None when it was."""
    marker = Path(path) / TREE_FILE
    try:
        data = marker.read_bytes()
    except FileNotFoundError:
        return f"{path} has no {TREE_FILE}, so no image build of this checkout prepared it"
    except OSError as error:
        return f"cannot read {marker}: {error.strerror}"
    try:
        entry = json.loads(data)
        paths = list(entry["paths"])
    except (ValueError, KeyError, TypeError):
        return f"{marker} is not a build record"
    if entry.get("component") != component:
        return f"{marker} records {entry.get('component')}, not {component}"
    if encode(record(root, component, paths)) != data:
        return f"{path} was prepared from other {component} sources than this checkout's"
    return None
