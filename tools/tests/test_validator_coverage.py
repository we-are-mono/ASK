"""A1b/A1c regression net — validator-table catalogs stay non-empty and
every PERMISSIVE_CMD has explicit acknowledgement.

Two checks at collection time, no kernel involvement:

  1. Sanity. EXACT and BOUNDED catalogs must be non-empty. A regression
     in `_cmd_catalog`'s parser (or someone deleting all CDX_CMD()
     registrations from a header by accident) shows up here before it
     hides a hole in test_fci_fuzz.py.

  2. Permissive coverage. Each PERMISSIVE entry must appear in
     golden/permissive_cmd_allowlist.yaml with a reason. The fuzzer
     skips PERMISSIVE entries (they have no length contract to assert
     against), so a *new* permissive command introduced silently would
     have zero coverage. Forcing the allowlist update makes the choice
     explicit: tighten the spec, or document why it stays permissive.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from _cmd_catalog import build_catalogs

ALLOWLIST_PATH = Path(__file__).parent / "golden" / "permissive_cmd_allowlist.yaml"


def _load_permissive_allowlist() -> dict[str, str]:
    raw = yaml.safe_load(ALLOWLIST_PATH.read_text()) or {}
    out: dict[str, str] = {}
    for entry in raw.get("allowlist") or []:
        name = entry.get("name")
        reason = entry.get("reason")
        if not name or not reason:
            raise AssertionError(
                f"permissive allowlist entry missing name/reason: {entry!r}"
            )
        if name in out:
            raise AssertionError(
                f"duplicate permissive allowlist entry for {name!r}"
            )
        out[name] = reason
    return out


def test_validator_catalogs_non_empty():
    exact, bounded, permissive = build_catalogs()
    assert exact, (
        "EXACT_CMDS is empty — _cmd_catalog parser may be broken or all "
        "CDX_CMD() registrations were removed from the source tree."
    )
    assert bounded, (
        "BOUNDED_CMDS is empty — A1b migration appears to have lost "
        "every CDX_CMD_VAR(min, max) entry."
    )
    # PERMISSIVE may legitimately go to zero as A1c finishes; don't
    # assert non-empty there.


def test_permissive_cmds_explicitly_acknowledged():
    """Every permissive cmd must be in the allowlist OR migrated.

    This is the tripwire: A1c's incremental migrations touch one
    subsystem at a time, and a *new* CDX_CMD_VAR(0, U16_MAX) introduced
    by other work would slip through test_fci_fuzz.py (which skips
    permissive). Forcing the allowlist update keeps the choice visible.
    """
    _, _, permissive = build_catalogs()
    allowlist = _load_permissive_allowlist()
    uncovered = sorted(name for name, _code in permissive if name not in allowlist)
    assert not uncovered, (
        f"{len(uncovered)} permissive command(s) lack allowlist entries:\n  "
        + "\n  ".join(uncovered)
        + f"\n\nEither tighten the spec to BOUNDED/EXACT in the cdx source, "
        f"or add entries to {ALLOWLIST_PATH.name} with a `reason` field."
    )
