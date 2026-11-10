"""Every NAPI that drains a QMan portal is kept out of busy polling.

A portal belongs to one CPU and is drained only by the poll its own interrupt
scheduled, with that interrupt masked: qman_p_poll_dqrr() BUG()s otherwise.
Busy polling calls a NAPI's poll from a socket's task, on any CPU, once a
received skb carried the NAPI's id, and GRO stamps every skb it takes with the
id of the NAPI it was handed. So each NAPI whose poll drains a portal -- the
portal's own, each DPAA port's, VWD's -- is registered NO_BUSY_POLL, which keeps
it out of the NAPI hash and leaves it no id to stamp. The DUT side is
tools/tests/dpaa_busy_poll.py.
"""

import re
from pathlib import Path

from _kernel_source import kernel_source

ROOT = Path(__file__).resolve().parents[2]
SDK = ("drivers/staging/fsl_qbman", "drivers/net/ethernet/freescale/sdk_dpaa")
# The SDK's entry points that dequeue from a portal's ring.
DRAINS = {"qman_poll_dqrr", "qman_p_poll_dqrr", "qman_poll", "qman_p_poll"}
# A definition starts at column 0, its return type on the same line or the one
# before (`static int\nfoo_poll(...)`).
DEFINITION = re.compile(r"^(?:\w[^\n;]*?[\s*])?(\w+)\s*\([^;{]*\)\s*\{", re.M)
CALL = re.compile(r"\b(\w+)\s*\(")
REGISTER = re.compile(r"\bnetif_napi_add(_weight|_tx|_tx_weight)?\s*\(")
# Named here so the check cannot pass by finding no registration at all.
EXPECTED = {("qman_high.c", "qman_portal_dqrr_poll"), ("dpaa_eth.c", "dpaa_eth_poll"),
            ("dpa_wifi.c", "dpaa_eth_poll")}


def code(text):
    """The source without its comments, which name these functions too."""
    return re.sub(r"//[^\n]*", "", re.sub(r"/\*.*?\*/", " ", text, flags=re.S))


def squash(expr):
    return re.sub(r"\s+", "", expr)


def arguments(text, start):
    """The top-level arguments of the call whose '(' is at start."""
    depth, args, current = 0, [], ""
    for i in range(start, len(text)):
        char = text[i]
        if char == "(":
            depth += 1
            if depth == 1:
                continue
        elif char == ")":
            depth -= 1
            if depth == 0:
                args.append(current.strip())
                return args
        elif char == "," and depth == 1:
            args.append(current.strip())
            current = ""
            continue
        current += char
    raise AssertionError(f"unbalanced call at {start}")


def draining_polls(sources):
    """Functions that dequeue from a portal, directly or through a callee."""
    calls = {}
    for text in sources.values():
        heads = [(m.start(), m.group(1)) for m in DEFINITION.finditer(text)]
        for i, (start, name) in enumerate(heads):
            end = heads[i + 1][0] if i + 1 < len(heads) else len(text)
            calls.setdefault(name, set()).update(CALL.findall(text[start:end]))
    names = set(DRAINS)
    while more := {name for name, called in calls.items() if called & names} - names:
        names |= more
    return names


def registrations(sources, polls):
    """(file, poll, napi, kept out of busy polling) for each NAPI added with
    a draining poll."""
    found = []
    for name, text in sources.items():
        for call in REGISTER.finditer(text):
            args = arguments(text, call.end() - 1)
            napi, poll = args[1], args[2]
            if poll not in polls:
                continue
            # The kernel's own NO_BUSY_POLL registration, or the bit set on the
            # same NAPI's state just before the add.
            state = f"{napi}.state" if napi.startswith("&") else f"&{napi}->state"
            before = text[max(0, call.start() - 200):call.start()]
            marked = bool(call.group(1) and call.group(1).startswith("_tx")) or squash(
                f"set_bit(NAPI_STATE_NO_BUSY_POLL,{state});") in squash(before)
            found.append((name, poll, napi, marked))
    return found


def check(kernel, cdx):
    sources = {path.name: code(path.read_text())
               for top in SDK for path in (kernel / top).rglob("*.c")}
    sources.update({path.name: code(path.read_text()) for path in cdx.glob("*.c")})
    found = registrations(sources, draining_polls(sources))
    assert EXPECTED <= {(name, poll) for name, poll, _, _ in found}, found
    busy = [(name, poll, napi) for name, poll, napi, marked in found if not marked]
    assert not busy, ("NAPIs that drain a QMan portal and can be busy-polled", busy)


def test_portal_napis_are_never_busy_polled():
    check(kernel_source(), ROOT / "cdx")
