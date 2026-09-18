"""Shared multicast rig plumbing: capturing on the LAN VM, and the oracles
that tell hardware replication apart from the bridge flooding in software.

The LAN VM is behind the DUT's NAT and has no IP path from the orchestrator,
so every one of these goes over the libvirt UART. Captures run as backgrounded
processes coordinated through pidfiles, because UART is a single channel and
two concurrent `lan.run` calls would interleave.
"""

from __future__ import annotations

import asyncio

import pytest_asyncio


# ---- capture (UART-driven, no LAN agent required) -------------------------

_TCPDUMP_PIDFILE_PREFIX = "/tmp/ask_mcast_tcpdump"


@pytest_asyncio.fixture
async def pcap_cleanup_lan(lan):
    """Tracks pcap paths created during a test; rm them on teardown so
    /tmp on the LAN VM doesn't accumulate over many parametrize runs.
    UART has direct shell access — single rm call suffices.
    """
    paths: list[str] = []
    yield paths
    if paths:
        try:
            lan.run("rm -f " + " ".join(paths), timeout=5)
        except Exception:
            pass


def spawn_parallel_tcpdumps(
    lan, ifaces: list[str], capfiles: list[str], bpf: str,
) -> None:
    """Launch one backgrounded tcpdump per (iface, capfile) on the LAN VM.

    Plain `tcpdump -w file &` (no -G/-W) so behaviour is portable across
    tcpdump/libpcap versions. Each tcpdump's PID goes into a sidecar file so
    the later kill is precise instead of `pkill -f tcpdump`-broad.

    A single UART command chains all spawns, so the round-trip is one shot
    regardless of N — and, more importantly, the captures start together.
    """
    chain = ""
    for iface, capfile in zip(ifaces, capfiles):
        pidfile = f"{_TCPDUMP_PIDFILE_PREFIX}_{iface}.pid"
        # `-Q in` records inbound only — excludes the egress copy AF_PACKET
        # would otherwise capture, so the count is what arrived at the
        # listener rather than what the listener also sent.
        chain += (
            f"nohup tcpdump -i {iface} -Q in -w {capfile} '{bpf}' "
            f"</dev/null >/dev/null 2>&1 & "
            f"echo $! > {pidfile}; "
        )
    chain += "echo SPAWNED"
    r = lan.run(chain, timeout=10)
    assert "SPAWNED" in r.stdout, (
        f"failed to spawn tcpdumps via UART: rc={r.rc}, out={r.stdout!r}"
    )


def kill_parallel_tcpdumps(lan, ifaces: list[str]) -> None:
    """SIGTERM the previously-spawned tcpdumps via their pid sidecars."""
    chain = ""
    for iface in ifaces:
        pidfile = f"{_TCPDUMP_PIDFILE_PREFIX}_{iface}.pid"
        # A missing pidfile or an already-dead pid must not fail the chain.
        chain += (
            f"[ -f {pidfile} ] && kill -TERM $(cat {pidfile}) "
            f"2>/dev/null; rm -f {pidfile}; "
        )
    chain += "echo KILLED"
    r = lan.run(chain, timeout=10)
    assert "KILLED" in r.stdout, (
        f"failed to kill tcpdumps: rc={r.rc}, out={r.stdout!r}"
    )


def read_pcap_count(lan, capfile: str, *, match: str = "UDP") -> int:
    """Parse a saved pcap via `tcpdump -r`; count summary lines matching."""
    r = lan.run(f"tcpdump -r {capfile} -nn 2>&1", timeout=10)
    if r.rc != 0:
        raise AssertionError(
            f"tcpdump -r {capfile} failed: rc={r.rc}, out={r.stdout!r}"
        )
    return sum(1 for ln in r.stdout.splitlines() if match in ln)


async def capture_parallel_window(
    lan, *, ifaces: list[str], capfiles: list[str], bpf: str,
    window_s: float = 2.0, match: str = "UDP",
) -> dict[str, int]:
    """Spawn parallel tcpdumps, sleep through the window, kill them, read the
    pcaps, return per-iface counts. Pure UART.

    The caller injects AFTER this returns from its start grace, not before.
    """
    spawn_parallel_tcpdumps(lan, ifaces, capfiles, bpf)
    # Tiny grace so tcpdumps are listening before any traffic arrives.
    await asyncio.sleep(0.4)
    await asyncio.sleep(window_s)
    kill_parallel_tcpdumps(lan, ifaces)
    # Tiny pause for the pcap writer to flush on TERM.
    await asyncio.sleep(0.2)
    return {
        iface: read_pcap_count(lan, cf, match=match)
        for iface, cf in zip(ifaces, capfiles)
    }
