"""ABI tripwire — fail CI on silent renumbering of CDX commands or ioctls.

The golden snapshot at golden/cdx_abi_snapshot.json pins:
  - every CMD_* code in EXACT/BOUNDED/PERMISSIVE buckets
  - every CDX_CTRL_* ioctl encoding

A renumber, deletion, or addition without bumping the snapshot fails this
test with a structured diff. To accept the change deliberately, regenerate:

    ASK_REGEN_ABI_SNAPSHOT=1 pytest tools/tests/test_abi_snapshot.py

The regenerated file goes in the same commit as the kernel/header change.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import _cmd_catalog as cat
import _ioctl as ic

GOLDEN_PATH = Path(__file__).parent / "golden" / "cdx_abi_snapshot.json"
SNAPSHOT_VERSION = 1


def _ioctl_encodings() -> dict[str, int]:
    return {
        k: v
        for k, v in vars(ic).items()
        if k.startswith("CDX_CTRL_") and isinstance(v, int)
    }


def _build_snapshot() -> dict:
    exact, bounded, permissive = cat.build_catalogs()
    return {
        "version": SNAPSHOT_VERSION,
        "_cmd_catalog": {
            "exact":      [list(t) for t in exact],
            "bounded":    [list(t) for t in bounded],
            "permissive": [list(t) for t in permissive],
            "counts": {
                "exact":      len(exact),
                "bounded":    len(bounded),
                "permissive": len(permissive),
            },
        },
        "_ioctl": _ioctl_encodings(),
    }


def _diff_dict(name: str, golden: dict, current: dict) -> list[str]:
    out: list[str] = []
    for k in sorted(set(golden) | set(current)):
        if k not in current:
            out.append(f"  - {name}.{k} = {golden[k]!r}  REMOVED")
        elif k not in golden:
            out.append(f"  + {name}.{k} = {current[k]!r}  ADDED")
        elif golden[k] != current[k]:
            out.append(f"  ~ {name}.{k}: {golden[k]!r} -> {current[k]!r}")
    return out


def _diff_pairs(name: str, golden_pairs: list, current_pairs: list) -> list[str]:
    g = {k: v for k, v in golden_pairs}
    c = {k: v for k, v in current_pairs}
    return _diff_dict(name, g, c)


def _diff(golden: dict, current: dict) -> list[str]:
    diffs: list[str] = []
    for bucket in ("exact", "bounded", "permissive"):
        diffs.extend(_diff_pairs(
            f"_cmd_catalog.{bucket}",
            golden["_cmd_catalog"][bucket],
            current["_cmd_catalog"][bucket],
        ))
    diffs.extend(_diff_dict(
        "_cmd_catalog.counts",
        golden["_cmd_catalog"]["counts"],
        current["_cmd_catalog"]["counts"],
    ))
    diffs.extend(_diff_dict("_ioctl", golden["_ioctl"], current["_ioctl"]))
    return diffs


def test_abi_snapshot():
    current = _build_snapshot()

    if os.environ.get("ASK_REGEN_ABI_SNAPSHOT") == "1":
        GOLDEN_PATH.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN_PATH.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")
        return

    assert GOLDEN_PATH.exists(), (
        f"missing golden snapshot at {GOLDEN_PATH}; "
        f"run with ASK_REGEN_ABI_SNAPSHOT=1 to create it."
    )
    golden = json.loads(GOLDEN_PATH.read_text())
    assert golden.get("version") == SNAPSHOT_VERSION, (
        f"snapshot version mismatch: file={golden.get('version')!r} "
        f"expected={SNAPSHOT_VERSION}"
    )

    diffs = _diff(golden, current)
    assert not diffs, (
        "CDX ABI drifted from golden snapshot. If this is intentional, "
        "regenerate with ASK_REGEN_ABI_SNAPSHOT=1 and commit the new file:\n"
        + "\n".join(diffs)
    )
