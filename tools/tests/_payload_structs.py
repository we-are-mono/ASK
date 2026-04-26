"""Best-effort sizeof() resolver for CDX_CMD payload structs.

The fuzzer's payload-mutation cases need to send a *correctly sized*
payload (otherwise the dispatcher rejects with ERR_WRONG_COMMAND_SIZE
before the handler ever sees it). This module parses cdx/*.h to derive
sizeof(struct) for each TYPE referenced from a CDX_CMD / CDX_CMD_V
registration.

Coverage is best-effort: structs with nested types we can't resolve
(function pointers, kernel-only types, deeply nested aggregates) are
returned as None and the test parametrization skips them.

Type widths (matches the cdx U8/U16/U32/U64 typedefs in cdx/types.h):
    U8  / u8  / uint8_t  / char    -> 1
    U16 / u16 / uint16_t           -> 2
    U32 / u32 / uint32_t           -> 4
    U64 / u64 / uint64_t           -> 8

Arrays use the integer constant from a `#define` table; non-numeric
expressions (sizeof(X), arithmetic) yield None for that struct.
"""

from __future__ import annotations

import re
from pathlib import Path

from _cmd_catalog import _repo_root


_PRIMITIVE_SIZES: dict[str, int] = {
    "U8": 1, "u8": 1, "uint8_t": 1, "char": 1, "S8": 1, "s8": 1, "int8_t": 1,
    "U16": 2, "u16": 2, "uint16_t": 2, "S16": 2, "s16": 2, "int16_t": 2,
    "U32": 4, "u32": 4, "uint32_t": 4, "S32": 4, "s32": 4, "int32_t": 4,
    "U64": 8, "u64": 8, "uint64_t": 8, "S64": 8, "s64": 8, "int64_t": 8,
}


_DEFINE_RE  = re.compile(r"^\s*#\s*define\s+(\w+)\s+(0x[0-9a-fA-F]+|\d+)\b", re.MULTILINE)
# Match: typedef struct [_tag]? { body } NAME [, *PNAME]?;
_TYPEDEF_RE = re.compile(
    r"typedef\s+struct\s+\w*\s*\{(.+?)\}\s*([A-Za-z_]\w*)\s*[,;]",
    re.DOTALL,
)
# A field line: "    TYPE   name [arr] [= ...] ;" — skip comments + macros.
_FIELD_RE   = re.compile(
    r"^\s*([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*(?:\[\s*([^]]+?)\s*\])?\s*;",
)


def _read(p: Path) -> str:
    try:
        return p.read_text(errors="replace")
    except OSError:
        return ""


def _strip_comments(txt: str) -> str:
    txt = re.sub(r"/\*.*?\*/", "", txt, flags=re.DOTALL)
    txt = re.sub(r"//.*?$", "", txt, flags=re.MULTILINE)
    return txt


def _eval_dim(expr: str | None, defines: dict[str, int]) -> int | None:
    if expr is None:
        return 1
    expr = expr.strip()
    try:
        return int(expr, 0)
    except ValueError:
        pass
    return defines.get(expr)


def _scan_headers() -> tuple[dict[str, int], dict[str, str]]:
    """Return (defines, struct_bodies). struct_bodies is name -> body."""
    root = _repo_root() / "cdx"
    defines: dict[str, int] = {}
    bodies: dict[str, str] = {}
    for hdr in sorted(root.glob("*.h")):
        raw = _strip_comments(_read(hdr))
        for m in _DEFINE_RE.finditer(raw):
            try:
                defines[m.group(1)] = int(m.group(2), 0)
            except ValueError:
                pass
        for m in _TYPEDEF_RE.finditer(raw):
            body, name = m.group(1), m.group(2)
            bodies[name] = body
    return defines, bodies


_DEFINES, _BODIES = _scan_headers()


def compute_struct_size(name: str, _seen: frozenset[str] | None = None) -> int | None:
    """sizeof(name) in bytes; None if unparseable."""
    _seen = (_seen or frozenset()) | {name}
    body = _BODIES.get(name)
    if body is None:
        return None
    total = 0
    for line in body.splitlines():
        m = _FIELD_RE.match(line)
        if not m:
            # Empty line, preprocessor, weird syntax — bail conservatively
            # only if the line looks like it should be a field.
            stripped = line.strip()
            if stripped and not stripped.startswith(("#", "//", "/*")):
                # Could be a multi-decl line ("U8 a, b, c;") or
                # function-pointer field — we can't size those reliably.
                if ";" in stripped:
                    return None
            continue
        type_name, _field, dim_expr = m.group(1), m.group(2), m.group(3)
        sz = _PRIMITIVE_SIZES.get(type_name)
        if sz is None:
            if type_name in _seen:
                return None  # recursive struct, bail
            sz = compute_struct_size(type_name, _seen)
            if sz is None:
                return None
        n = _eval_dim(dim_expr, _DEFINES)
        if n is None:
            return None
        total += sz * n
    return total


def sizes_for_commands(
    cmd_to_type: dict[str, str],
) -> dict[str, int]:
    """Map cmd_name -> arg_size for every cmd whose TYPE we can size."""
    out: dict[str, int] = {}
    for cmd_name, type_name in cmd_to_type.items():
        sz = compute_struct_size(type_name)
        if sz is not None and sz > 0:
            out[cmd_name] = sz
    return out
