"""Source-driven catalog of FCI command-code registrations.

Scans the cdx/ tree at test-collection time to enumerate every CDX_CMD*
registration, classifying each by the length contract its spec enforces.
The fuzzer uses this to parametrize across the full ~120-code surface
without maintaining a hand-curated list.

Classification:
  EXACT_CMDS       — CDX_CMD, CDX_CMD_V, CDX_CMD_NOARG.
                     Dispatcher enforces length == spec->arg_size.
                     Any other length → ERR_WRONG_COMMAND_SIZE.
  BOUNDED_CMDS     — CDX_CMD_VAR(min, max) with min > 0 OR max < U16_MAX.
                     Dispatcher accepts [min, max]; anything outside →
                     ERR_WRONG_COMMAND_SIZE.
  PERMISSIVE_CMDS  — CDX_CMD_VAR(0, U16_MAX). Dispatcher doesn't check;
                     handler owns rejection. Skipped by the generic
                     fuzzer — covered by per-subsystem tests instead.
                     See ISSUES.md A1b item 6.

The catalog reads from $ASK_SRCROOT (default: two levels up from
tools/tests/, i.e. the repo root).
"""

from __future__ import annotations

import os
import re
from pathlib import Path


U16_MAX = 0xFFFF

_CMD_DEFINE_RE = re.compile(
    r"^\s*#\s*define\s+(CMD_\w+)\s+(0x[0-9a-fA-F]+|\d+)\b",
    re.MULTILINE,
)
_CDX_CMD_RE       = re.compile(r"\bCDX_CMD\s*\(\s*(CMD_\w+)\s*,\s*([A-Za-z_]\w*)")
_CDX_CMD_V_RE     = re.compile(r"\bCDX_CMD_V\s*\(\s*(CMD_\w+)\s*,\s*([A-Za-z_]\w*)")
_CDX_CMD_NOARG_RE = re.compile(r"\bCDX_CMD_NOARG\s*\(\s*(CMD_\w+)\b")
_CDX_CMD_NOARG_V_RE = re.compile(r"\bCDX_CMD_NOARG_V\s*\(\s*(CMD_\w+)\b")
_CDX_CMD_VAR_RE   = re.compile(
    r"\bCDX_CMD_VAR\s*\(\s*(CMD_\w+)\s*,\s*([^,]+?)\s*,\s*([^,]+?)\s*,",
)


def _repo_root() -> Path:
    if env := os.environ.get("ASK_SRCROOT"):
        return Path(env)
    # tools/tests/_cmd_catalog.py → repo root is ../../
    return Path(__file__).resolve().parents[2]


def _parse_code_defines(headers: list[Path]) -> dict[str, int]:
    """Build CMD_* → numeric code map from a set of headers."""
    out: dict[str, int] = {}
    for h in headers:
        try:
            txt = h.read_text(errors="replace")
        except OSError:
            continue
        for m in _CMD_DEFINE_RE.finditer(txt):
            name, val = m.group(1), m.group(2)
            out[name] = int(val, 0)
    return out


def _eval_bound(expr: str, code_map: dict[str, int]) -> int | None:
    """Best-effort eval of a CDX_CMD_VAR bound like `sizeof(Foo)`, `0`,
    `U16_MAX`, `MC4_MIN_COMMAND_SIZE`. Returns None if we can't determine.
    """
    expr = expr.strip()
    if expr == "U16_MAX":
        return U16_MAX
    if expr == "0":
        return 0
    try:
        return int(expr, 0)
    except ValueError:
        pass
    if expr in code_map:
        return code_map[expr]
    # sizeof(X), MIN_SIZE macros etc. — unknown at parse time. Caller
    # treats unknown as "not (0, U16_MAX)", which is safe: we'll skip
    # cases we can't reason about rather than false-fail.
    return None


# Guard macros that are never defined at build time. Any CDX_CMD entry
# inside these #ifdef blocks is compiled out — the kernel never sees it
# and the dispatcher returns ERR_UNKNOWN_COMMAND for that code. The
# catalog must skip them to match reality.
_DISABLED_GUARDS = frozenset({
    "CDX_TODO_IPSEC",
    "CDX_TODO_TUNNEL",
    "CDX_TODO_MC",
    "CDX_TODO_PPPOE",
    "CDX_TODO_VLAN",
    "CDX_TODO_RX",
    "CDX_TODO_TX",
    "CDX_TODO_QM",
    "CDX_TODO_STAT",
    "CDX_TODO_BRIDGE",
    "CDX_TODO_WIFI",
    "CDX_TODO_RTP",
    "CDX_TODO_IPV4",
    "CDX_TODO_IPV6",
})

_IFDEF_RE  = re.compile(r"^\s*#\s*if(n?def)?\s+(\w+)", re.MULTILINE)
_ENDIF_RE  = re.compile(r"^\s*#\s*endif\b", re.MULTILINE)


def _strip_disabled_ifdefs(txt: str) -> str:
    """Remove text inside #ifdef <DISABLED> ... #endif blocks.

    Simple line-by-line walk tracking nest depth. Doesn't try to
    evaluate real conditionals — only filters guards that are in the
    known-always-off set, and only tracks depth for those. Other
    #ifdefs pass through untouched so regex matching behaves as before.
    """
    out: list[str] = []
    skip_depth = 0
    lines = txt.splitlines(keepends=True)
    for line in lines:
        if skip_depth > 0:
            m = _IFDEF_RE.match(line)
            if m and m.group(2) in _DISABLED_GUARDS:
                skip_depth += 1
            elif _ENDIF_RE.match(line):
                skip_depth -= 1
            # otherwise: line is inside a skipped block, drop it
            continue
        m = _IFDEF_RE.match(line)
        if m and m.group(2) in _DISABLED_GUARDS:
            skip_depth = 1
            continue   # swallow the #ifdef line itself too
        out.append(line)
    return "".join(out)


def _scan_sources(src_files: list[Path], code_map: dict[str, int]):
    """Yield (kind, name, code, extra) tuples for every CDX_CMD* site.

    For exact-spec entries with a payload type (CDX_CMD / CDX_CMD_V),
    extra carries the type name; for noarg / var entries it's None or
    the (lo, hi) tuple respectively.
    """
    for f in src_files:
        try:
            raw = f.read_text(errors="replace")
        except OSError:
            continue
        txt = _strip_disabled_ifdefs(raw)
        for m in _CDX_CMD_NOARG_V_RE.finditer(txt):
            name = m.group(1)
            if name in code_map:
                yield ("exact", name, code_map[name], None)
        for m in _CDX_CMD_NOARG_RE.finditer(txt):
            name = m.group(1)
            if name in code_map:
                yield ("exact", name, code_map[name], None)
        for m in _CDX_CMD_V_RE.finditer(txt):
            name, type_name = m.group(1), m.group(2)
            if name in code_map:
                yield ("exact", name, code_map[name], type_name)
        for m in _CDX_CMD_RE.finditer(txt):
            name, type_name = m.group(1), m.group(2)
            if name in code_map:
                yield ("exact", name, code_map[name], type_name)
        for m in _CDX_CMD_VAR_RE.finditer(txt):
            name, min_e, max_e = m.group(1), m.group(2), m.group(3)
            if name not in code_map:
                continue
            lo = _eval_bound(min_e, code_map)
            hi = _eval_bound(max_e, code_map)
            yield ("var", name, code_map[name], (lo, hi))


def _src_paths(root: Path) -> list[Path]:
    return [p for p in (
        sorted((root / "cdx").glob("control_*.c"))
        + [root / "cdx" / "dpa_control_mc.c", root / "cdx" / "cdx_dev.c"]
    ) if p.is_file()]


def build_catalogs() -> tuple[list[tuple[str, int]], list[tuple[str, int]], list[tuple[str, int]]]:
    """Return (exact, bounded, permissive) lists of (name, code).

    Each list is sorted and deduped. Bounded CMD_VAR entries drop the
    (min, max) once classified — tests just need the code, they use
    length=0 (below any min > 0) as the always-invalid mutation.
    """
    root = _repo_root()
    header_paths = [
        root / "cdx" / "cdx_cmdhandler.h",
        root / "cdx" / "cdx_ioctl.h",
    ]
    code_map = _parse_code_defines(header_paths)

    exact: set[tuple[str, int]] = set()
    bounded: set[tuple[str, int]] = set()
    permissive: set[tuple[str, int]] = set()

    for kind, name, code, extra in _scan_sources(_src_paths(root), code_map):
        if kind == "exact":
            exact.add((name, code))
        else:
            lo, hi = extra
            if lo == 0 and hi == U16_MAX:
                permissive.add((name, code))
            else:
                # Includes cases where lo or hi couldn't be resolved —
                # we conservatively treat those as "has some bound" and
                # let the tests probe with length=0, which is below any
                # positive min.
                bounded.add((name, code))

    return (
        sorted(exact,      key=lambda x: x[1]),
        sorted(bounded,    key=lambda x: x[1]),
        sorted(permissive, key=lambda x: x[1]),
    )


def exact_payload_types() -> dict[str, str]:
    """Map cmd_name -> payload type-name for CDX_CMD / CDX_CMD_V sites.

    Only covers entries that carry a TYPE arg (so CDX_CMD_NOARG is
    omitted — it has no payload). Used by the payload-mutation fuzzer
    to look up sizeof(TYPE) via _payload_structs.
    """
    root = _repo_root()
    header_paths = [
        root / "cdx" / "cdx_cmdhandler.h",
        root / "cdx" / "cdx_ioctl.h",
    ]
    code_map = _parse_code_defines(header_paths)

    out: dict[str, str] = {}
    for kind, name, _code, extra in _scan_sources(_src_paths(root), code_map):
        if kind == "exact" and isinstance(extra, str):
            out[name] = extra
    return out
