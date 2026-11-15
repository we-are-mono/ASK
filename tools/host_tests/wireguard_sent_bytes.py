"""WireGuard's count of the bytes sent to a peer, compiled from the kernel.

The transmit lanes send one peer's packets from several CPUs at once, each
lane through wg_socket_send_skb_to_peer(), which holds the peer's endpoint
lock only shared: it keeps the endpoint from changing under the send, not one
lane from another. The bytes sent are added there, and by the fast path's
seal, on whichever CPU seals, so the peer's count has to take concurrent adds
without losing any, and the count netlink reports has to be the one both add
to.
"""

import os
from pathlib import Path
import re

from ask_orch.process import run_process
from _kernel_source import kernel_source

WIREGUARD = Path("drivers/net/wireguard")


def function(source, name):
    # The line has to begin with a word, the return type: a comment line that
    # names `foo()' would otherwise match and run on to the next definition.
    match = re.search(r"^(?:static )?\w[^\n]*\b" + name + r"\([^;]*?\)\s*\{", source, re.M)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


def _code(source):
    """C source without its comments, which name the fields too."""
    return re.sub(r"/\*.*?\*/|//[^\n]*", "", source, flags=re.S)


def _sent_counter(peer):
    """The declaration in struct wg_peer of tx_bytes, as the tree writes it."""
    body = re.search(r"^struct wg_peer \{(.*?)^\};", _code(peer), re.M | re.S)
    assert body, "struct wg_peer"
    declarations = [" ".join(d.split()) for d in body[1].split(";")
                    if re.search(r"\btx_bytes\b", d)]
    assert len(declarations) == 1, declarations
    return declarations[0] + ";\n"


def test_lanes_sending_to_one_peer_count_every_byte(tmp_path):
    """Every lane sends to one peer at once; the peer counts every byte sent,
    and no add races another (ThreadSanitizer fails the run on one)."""
    wireguard = kernel_source() / WIREGUARD
    peer = (wireguard / "peer.h").read_text()
    lanes = re.search(r"^#define WG_MAX_TX_LANES\s+(\d+)", peer, re.M)
    (tmp_path / "wireguard_sent_counter.inc").write_text(_sent_counter(peer))
    (tmp_path / "wireguard_send_production.inc").write_text(
        function((wireguard / "socket.c").read_text(), "wg_socket_send_skb_to_peer"))
    binary = tmp_path / "wireguard_sent_bytes"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra",
        "-Werror", "-Wno-unused-parameter", "-fsanitize=thread", "-pthread",
        # One lane where the tree has none: nothing then sends at once.
        f"-DLANES={max(int(lanes[1]) if lanes else 1, 1)}",
        "-I", str(tmp_path),
        str(Path(__file__).with_name("wireguard_sent_bytes.c")), "-o", str(binary),
    ], check=True)
    result = run_process([str(binary)], text=True, capture_output=True, timeout=120, env={
        **os.environ, "TSAN_OPTIONS": "halt_on_error=1:exitcode=66:report_signal_unsafe=0",
    })
    assert result.returncode == 0, result.stdout + result.stderr
    assert "all counted" in result.stdout


def test_one_counter_for_the_bytes_sent():
    """The socket's send and the fast path's seal add to one counter of the
    peer, and netlink reports that counter as it is: a second counter beside
    it, summed only where it is reported, is a second place the same bytes
    can be lost or told twice."""
    wireguard = kernel_source() / WIREGUARD
    send = function(_code((wireguard / "socket.c").read_text()), "wg_socket_send_skb_to_peer")
    sent = (re.findall(r"\bpeer->(\w+)\s*\+=\s*skb_len\b", send)
            + re.findall(r"\batomic64_add\(\s*skb_len\s*,\s*&peer->(\w+)\s*\)", send))
    assert len(sent) == 1, f"the send adds the bytes it sent to {sent}"
    counters = {"the send": sent[0]}
    fastpath = wireguard / "fastpath.c"
    if fastpath.exists():
        seal = function(_code(fastpath.read_text()), "wg_fastpath_seal")
        sealed = re.findall(r"\batomic64_add\([^;]*?,\s*&peer->(\w*bytes)\s*\)", seal)
        assert len(sealed) == 1, f"the seal adds the bytes it sealed to {sealed}"
        counters["the seal"] = sealed[0]
    assert len(set(counters.values())) == 1, \
        "one peer's sent bytes are counted in " + " and ".join(
            f"{field} ({who})" for who, field in counters.items())
    netlink = _code((wireguard / "netlink.c").read_text())
    reported = re.search(r"WGPEER_A_TX_BYTES\s*,(.*?),\s*WGPEER_A_UNSPEC\s*\)", netlink, re.S)
    assert reported, "WGPEER_A_TX_BYTES"
    reported = " ".join(reported[1].split())
    assert reported == f"atomic64_read(&peer->{sent[0]})", \
        f"netlink reports {reported!r} as the bytes sent, not the counter {sent[0]} both add to"
