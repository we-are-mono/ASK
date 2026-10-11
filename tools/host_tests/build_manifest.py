"""An image counts for a checkout only when that checkout built it: each
component's build record and the device tree's (ask_orch.manifest)."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys

import pytest

from ask_orch import build_record, manifest
from ask_orch.provenance import IMAGE

ROOT = Path(__file__).resolve().parents[2]
KERNEL_RECIPE = "meta-ask/recipes-kernel/linux/linux-ask_6.12.bb"
CDX_RECIPE = "meta-ask/recipes-ask/cdx/cdx_1.0.bb"
# What each recipe of the fixture layer records, as the class derives it: the
# recipe, its local sources, its external tree, its declared directories.
INPUTS = {manifest.KERNEL: [KERNEL_RECIPE, "patches/kernel/010-one.patch", "patches/kernel"],
          "cdx": [CDX_RECIPE, "cdx"]}


def git(root, *args):
    subprocess.run(["git", *args], cwd=root, capture_output=True, check=True)


@pytest.fixture
def checkout(tmp_path):
    """A layer of two recipes: a kernel built from a patch series, and a
    module built from an external tree with ignored build output beside its
    source."""
    for name, text in {
            ".gitignore": "*.o\nmeta-ask/build/\n",
            KERNEL_RECIPE: "SRC_URI = file://010-one.patch\n",
            "patches/kernel/010-one.patch": "the kernel change\n",
            CDX_RECIPE: "EXTERNALSRC = cdx\n",
            "cdx/cdx_main.c": "int cdx;\n",
            "cdx/cdx_main.o": "build output\n"}.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    git(tmp_path, "init", "-q")
    git(tmp_path, "add", "-A")
    git(tmp_path, "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
        "commit", "-qm", "fixture")
    return tmp_path


def build(root, out):
    """What an image build of `root`, as it is now, leaves: a record per
    recipe in the build tree and in the image, and the device tree's digest
    of the kernel's."""
    records = out / "records"
    records.mkdir()
    for name, paths in INPUTS.items():
        data = build_record.encode(build_record.record(root, name, paths))
        (records / f"{name}.json").write_bytes(data)
        kept = root / manifest.BUILD_RECORDS.format(name).replace("*", "arch", 1).replace("*", "1.0")
        kept.parent.mkdir(parents=True, exist_ok=True)
        kept.write_bytes(data)
    devicetree = out / manifest.DEVICETREE_PROPERTY
    devicetree.write_bytes(
        manifest.digest((records / f"{manifest.KERNEL}.json").read_bytes()).encode() + b"\0")
    return records, devicetree


def report(records, devicetree):
    """What the DUT reports of an installed build, from the image script."""
    result = subprocess.run(
        [sys.executable, "-c", IMAGE + f"RECORDS = {str(records)!r}\nDEVICETREE = {str(devicetree)!r}\n"
         "print(json.dumps(build()))\n"], capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


def test_an_image_built_from_the_checkout_matches_it(checkout, tmp_path_factory):
    image = report(*build(checkout, tmp_path_factory.mktemp("image")))
    assert sorted(image["build"]) == manifest.components(checkout) == ["cdx", manifest.KERNEL]
    # A file in a recorded directory adds nothing to the inputs.
    assert image["build"][manifest.KERNEL]["paths"] == [KERNEL_RECIPE, "patches/kernel"]
    assert manifest.verify(checkout, image) == []


@pytest.mark.parametrize("change, problems", [
    # Anything the build reads, tracked or not, committed or not, named.
    (lambda root: (root / "cdx/cdx_main.c").write_text("int changed;\n"),
     ["cdx: built from other sources than this checkout's (cdx/cdx_main.c)"]),
    (lambda root: (root / "cdx/cdx_new.c").write_text("int added;\n"),
     ["cdx: built from other sources than this checkout's (cdx/cdx_new.c)"]),
    (lambda root: (root / "cdx/cdx_main.c").unlink(),
     ["cdx: built from other sources than this checkout's (cdx/cdx_main.c)"]),
    (lambda root: (root / CDX_RECIPE).write_text("# a comment is still the recipe\n"),
     [f"cdx: built from other sources than this checkout's ({CDX_RECIPE})"]),
    (lambda root: (root / "patches/kernel/010-one.patch").write_text("revised\n"),
     ["linux-ask: built from other sources than this checkout's (patches/kernel/010-one.patch)"]),
    # A patch beside the series: the directory is recorded whole, and the
    # series test below keeps the two the same.
    (lambda root: (root / "patches/kernel/020-new.patch").write_text("x\n"),
     ["linux-ask: built from other sources than this checkout's (patches/kernel/020-new.patch)"]),
    # Nothing the build reads: its own output, and a mode bitbake's
    # checksums never see.
    (lambda root: (root / "cdx/cdx_main.o").write_text("rebuilt\n"), []),
    (lambda root: (root / "cdx/cdx_main.c").chmod(0o755), []),
], ids=["edited", "added", "removed", "recipe", "kernel-patch", "series-directory",
        "ignored-output", "mode"])
def test_a_change_to_a_component_input_marks_only_that_component(checkout, tmp_path_factory, change,
                                                                 problems):
    image = report(*build(checkout, tmp_path_factory.mktemp("image")))
    change(checkout)
    assert manifest.verify(checkout, image) == problems


def test_an_image_the_build_tree_did_not_last_build_is_named_as_such(checkout, tmp_path_factory):
    image = report(*build(checkout, tmp_path_factory.mktemp("image")))
    (checkout / "cdx/cdx_main.c").write_text("int changed;\n")
    build(checkout, tmp_path_factory.mktemp("rebuilt"))
    assert manifest.verify(checkout, image) == [
        "cdx: built from other sources than this checkout's (not what this build tree last built)"]


def test_a_recipe_without_checkout_inputs_records_no_files(checkout):
    """git names the whole checkout for no paths; a record of nothing must
    not, or every edit anywhere would rebuild that recipe."""
    assert build_record.record(checkout, "firmware", []) == {
        "component": "firmware", "paths": [], "files": {}}


def test_only_the_checkouts_own_ignore_rules_count(checkout, tmp_path_factory, monkeypatch):
    """kas runs bitbake with a home of its own; a user's global excludes must
    not make the harness drop a file the build recorded."""
    home = tmp_path_factory.mktemp("home")
    (home / "excludes").write_text("*.local\n")
    (home / ".gitconfig").write_text(f"[core]\n\texcludesFile = {home / 'excludes'}\n")
    (checkout / "cdx/notes.local").write_text("an input as far as the checkout says\n")
    recorded = build_record.names(checkout, ["cdx"])
    monkeypatch.setenv("HOME", str(home))
    assert build_record.names(checkout, ["cdx"]) == recorded
    assert "cdx/notes.local" in recorded


def test_the_layer_and_the_image_must_carry_the_same_components(checkout, tmp_path_factory):
    image = report(*build(checkout, tmp_path_factory.mktemp("image")))
    added = checkout / "meta-ask/recipes-ask/flowtable/ask-flowtable_1.0.bb"
    added.parent.mkdir(parents=True)
    added.write_text("EXTERNALSRC = flowtable\n")
    (checkout / CDX_RECIPE).unlink()
    assert manifest.verify(checkout, image) == [
        "ask-flowtable: the image carries no record of it",
        "cdx: no recipe in this checkout builds it"]


def test_an_unreadable_record_is_a_difference_not_an_error(checkout, tmp_path_factory):
    records, devicetree = build(checkout, tmp_path_factory.mktemp("image"))
    (records / "cdx.json").write_text("{}")
    assert manifest.verify(checkout, report(records, devicetree)) == [
        "cdx: the image's record of it is unreadable"]


def test_the_device_tree_must_come_from_the_kernel_build(checkout, tmp_path_factory):
    records, devicetree = build(checkout, tmp_path_factory.mktemp("image"))
    devicetree.write_bytes(b"0" * 64 + b"\0")
    assert manifest.verify(checkout, report(records, devicetree)) == [
        "device tree: compiled by another kernel build"]
    devicetree.unlink()
    assert manifest.verify(checkout, report(records, devicetree)) == [
        f"device tree: carries no {manifest.DEVICETREE_PROPERTY}"]


def test_a_source_tree_is_checked_against_its_component(checkout, tmp_path):
    tree = tmp_path / "kernel-source"
    tree.mkdir()
    assert "has no .ask-provenance.json" in manifest.tree(checkout, tree, manifest.KERNEL)
    (tree / manifest.TREE_FILE).write_bytes(
        build_record.encode(build_record.record(checkout, manifest.KERNEL, INPUTS[manifest.KERNEL])))
    assert manifest.tree(checkout, tree, manifest.KERNEL) is None
    assert "records linux-ask, not cdx" in manifest.tree(checkout, tree, "cdx")
    (checkout / "patches/kernel/010-one.patch").write_text("revised\n")
    assert "prepared from other linux-ask sources" in manifest.tree(checkout, tree, manifest.KERNEL)
    (tree / manifest.TREE_FILE).write_text("{")
    assert "is not a build record" in manifest.tree(checkout, tree, manifest.KERNEL)
    (tree / manifest.TREE_FILE).chmod(0)
    if os.geteuid():
        assert "cannot read" in manifest.tree(checkout, tree, manifest.KERNEL)


def test_every_recipe_in_the_layer_records_its_inputs():
    """A recipe without the class leaves the image without its record, and
    the first DUT run of a release would be the one to find out."""
    recipes = sorted((ROOT / "meta-ask").glob("recipes-*/*/*.bb"))
    assert len(recipes) == len(manifest.components(ROOT))
    for recipe in recipes:
        assert re.search(r"^inherit\b.*\bask-provenance\b", recipe.read_text(), re.M), recipe
    assert {manifest.KERNEL, "ask-image", "cdx", "ask-flowtable"} <= set(manifest.components(ROOT))


def test_the_kernel_series_is_every_patch_in_patches_kernel():
    """The host tests and the image compile the series the recipe lists; a
    patch only in the directory would be in the checkout and the kernel
    record, yet in neither tree."""
    recipe = (ROOT / KERNEL_RECIPE).read_text()
    listed = re.findall(r"file://(\S+\.patch)", recipe)
    assert sorted(listed) == sorted(path.name for path in (ROOT / "patches/kernel").iterdir())
