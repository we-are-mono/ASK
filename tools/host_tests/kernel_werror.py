"""Every build of the test kernel fails on a compiler warning, as OpenWrt's
build of the same kernel does: ask.cfg sets CONFIG_WERROR, the recipe merges
ask.cfg in every build mode, and no other fragment turns it off."""

from pathlib import Path
import re

FILES = Path(__file__).resolve().parents[2] / "meta-ask/recipes-kernel/linux/files"
RECIPE = FILES.parent / "linux-ask_6.12.bb"
WERROR = re.compile(r"^(?:CONFIG_WERROR=\S*|# CONFIG_WERROR is not set)$", re.M)


def merged_fragments():
    """Each fragment do_configure appends to .config, with whether a shell
    condition (a build mode) guards it."""
    body = re.search(r"^do_configure:append\(\) \{$(.*?)^\}$", RECIPE.read_text(), re.M | re.S)
    assert body, "no do_configure:append in the kernel recipe"
    depth, merged = 0, []
    for line in map(str.strip, body.group(1).splitlines()):
        if line.startswith("if "):
            depth += 1
        elif line == "fi":
            depth -= 1
        cat = re.fullmatch(r"cat \$\{UNPACKDIR\}/(\S+) >> \$\{B\}/\.config", line)
        if cat:
            merged.append((cat.group(1), depth > 0))
    return merged


def test_ask_cfg_sets_werror():
    assert WERROR.findall((FILES / "ask.cfg").read_text()) == ["CONFIG_WERROR=y"]


def test_every_mode_merges_ask_cfg():
    assert ("ask.cfg", False) in merged_fragments()


def test_no_other_fragment_turns_werror_off():
    for fragment in sorted(FILES.iterdir()):
        if fragment.name != "ask.cfg":
            assert set(WERROR.findall(fragment.read_text())) <= {"CONFIG_WERROR=y"}, fragment.name
