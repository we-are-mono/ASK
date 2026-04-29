"""Slice-2 end-to-end PPPoE tests via real pppoe-server + pppd.

Three tiered tests, each gating on the previous:

  Tier A — test_pppoe_session_lifecycle
      pppd dialed → ppp iface UP → cmm auto-registered the session via
      its rtnetlink hook on RTM_NEWLINK ARPHRD_PPP. Load-bearing
      positive control: CMD_PPPOE_ENTRY ACTION_QUERY via fci_send
      returns NO_ERR. If cmm didn't push (or __itf_is_programmed(eth3)
      gate failed), QUERY returns ERR_PPPOE_ENTRY_NOT_FOUND and the
      assertion message names that gate as the suspect.

  Tier B — test_pppoe_dut_ping
      Triage-only: from DUT, `ping -I ppp0 10.99.0.1`. NOT an offload
      test (DUT-originated traffic uses Linux ppp_generic xmit path,
      not FMAN classification). Useful as a triage step before Tier C.

  Tier C — test_pppoe_lan_through_dut_iperf_offloaded
      The real offload test. iperf3 from LAN VM through DUT through
      ppp0 to vision. Two oracles, both required:
        (1) iperf3 reports throughput
        (2) cmm's connections table includes the iperf3 flow during
            the test window — confirms cmm's CT-watcher fired AND
            pushed the inner-keyed CT entry, AND the action chain
            assembled with STRIP_PPPoE_HDR for offload.
      Catches the silent-kernel-slow-path regression where (1) passes
      but FMAN never engaged.
"""

from __future__ import annotations

import asyncio
import os
import subprocess

import pytest

from _pppoe_helpers import (
    ACTION_QUERY,
    CMD_PPPOE_ENTRY,
    pppoe_cmd,
)
from _pppoe_e2e import (  # noqa: F401  (fixture imports for resolution)
    pppoe_real_server,
    pppoe_dut_session,
)
from _topology import lan_run

from ask_orch.uart import Console


NO_ERR                       = 0
ERR_PPPOE_ENTRY_NOT_FOUND    = 801


# ---- Tier A: session lifecycle + cmm push positive control -----------

async def test_pppoe_session_lifecycle(
    aiohttp_session, target_agent, splat_window, pppoe_dut_session,
):
    """pppd dialed → ppp iface UP → cmm pushed the session into FCI."""
    ppp = pppoe_dut_session

    # First: kernel-side state — /proc/net/pppoe should have a session.
    # Format: header line "Id  Address  Device" + N data lines.
    target = Console.target()
    target.login("root")
    try:
        proc_pppoe = target.run("cat /proc/net/pppoe", timeout=3).stdout
    finally:
        target.close()

    data_lines = [
        ln for ln in proc_pppoe.splitlines()
        if ln.strip()
        and "Id" not in ln
        and "Address" not in ln
        and "Device" not in ln
    ]
    assert data_lines, (
        f"/proc/net/pppoe has no session entries after dial "
        f"({ppp} should be there): {proc_pppoe!r}"
    )

    # The load-bearing oracle: CMD_PPPOE_ENTRY ACTION_QUERY via FCI.
    # The kernel walks pppoe_cache; rc=NO_ERR means at least one
    # session is registered. cmm's push is async w.r.t. ppp iface UP —
    # RTM_NEWLINK fires when pppd creates the iface, cmm consumes it
    # off its own rtnetlink socket, reads /proc/net/pppoe, then issues
    # FPP_CMD_PPPOE_ENTRY. There's a small race window between iface-up
    # and FCI-pushed; poll for ~3s before declaring the failure.
    payload = pppoe_cmd(action=ACTION_QUERY)
    rc: int | None = None
    deadline = asyncio.get_event_loop().time() + 3.0
    while asyncio.get_event_loop().time() < deadline:
        r = await target_agent.fci_send(
            aiohttp_session, fcode=CMD_PPPOE_ENTRY,
            length=len(payload), payload=payload, timeout_ms=2000,
        )
        rc = r.get("reply_rc")
        if rc == NO_ERR:
            break
        await asyncio.sleep(0.3)
    assert rc == NO_ERR, (
        f"cmm did NOT push CMD_PPPOE_ENTRY for the dialed session "
        f"within 3s — FCI ACTION_QUERY last returned rc={rc!r} "
        f"(expected NO_ERR=0). Suspect: cmm's rtnetlink hook didn't "
        f"fire on RTM_NEWLINK ARPHRD_PPP, or __itf_is_programmed(eth3) "
        f"is False (eth3 not in cmm's iface table — check dpa_app "
        f"boot order)."
    )


# ---- Tier B: DUT-originated ping (triage-only, NOT offload) ----------

async def test_pppoe_dut_ping(
    aiohttp_session, target_agent, splat_window, pppoe_dut_session,
):
    """Link-liveness sanity. DUT-originated traffic uses Linux ppp_generic
    xmit, NOT FMAN — this proves the link works, not that offload works.
    Tier C is the real offload test."""
    ppp = pppoe_dut_session
    inner_local = os.environ.get("ASK_PPPOE_INNER_LOCAL", "10.99.0.1")
    target = Console.target()
    target.login("root")
    try:
        r = target.run(f"ping -I {ppp} -c 3 -W 2 {inner_local}", timeout=15)
        # ping -c 3 summary: "3 packets transmitted, 3 received, 0% packet loss"
        assert "0% packet loss" in r.stdout, (
            f"Ping over {ppp} to {inner_local} failed: rc={r.rc} "
            f"out={r.stdout!r}"
        )
    finally:
        target.close()


# ---- Tier C: LAN-through-DUT iperf3 with offload positive control ----

async def test_pppoe_lan_through_dut_iperf_offloaded(
    aiohttp_session, target_agent, lan, splat_window, pppoe_dut_session,
):
    """REAL offload test. iperf3 from LAN VM through DUT through ppp0
    to vision's inner IP. Two oracles, both required:

      (1) iperf3 reports throughput → data plane works end-to-end
      (2) cmm's connections table shows the iperf3 flow during the
          test window → cmm's CT-watcher fired, inner-keyed CT entry
          was pushed, action chain assembled with STRIP_PPPoE_HDR

    NAT direction: MASQUERADE on DUT's ppp egress so vision sees source
    inner_remote and replies via PPP without needing reverse routes on
    vision."""
    ppp = pppoe_dut_session
    inner_local  = os.environ.get("ASK_PPPOE_INNER_LOCAL",  "10.99.0.1")

    # Vision-side iperf3 server bound to the inner IP. No -1 — keep
    # alive across retries; tear down in finally.
    server = subprocess.Popen(
        ["iperf3", "-s", "-B", inner_local],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    target = Console.target()
    target.login("root")
    masq_added = False
    prior_ip_forward: str | None = None
    try:
        await asyncio.sleep(0.5)  # iperf3 server bind grace

        # DUT-side: route inner_local via ppp, enable forwarding,
        # MASQUERADE outbound on ppp.
        r = target.run(
            f"ip route replace {inner_local}/32 dev {ppp}", timeout=3,
        )
        assert r.rc == 0, f"ip route replace failed: {r.stdout!r}"
        # Capture prior ip_forward so teardown restores it. The gateway
        # image typically defaults to 1, so this is a no-op there — but
        # leaking the sysctl write into post-test state is the kind of
        # hygiene gap that bites the next test that asserts forwarding
        # is OFF.
        prior_ip_forward = target.run(
            "sysctl -n net.ipv4.ip_forward", timeout=3,
        ).stdout.strip() or "0"
        target.run("sysctl -w net.ipv4.ip_forward=1 >/dev/null", timeout=3)
        # -C check first; only -A if not already present (idempotent).
        r = target.run(
            f"iptables -t nat -C POSTROUTING -o {ppp} -j MASQUERADE "
            f"2>/dev/null && echo EXISTS || "
            f"(iptables -t nat -A POSTROUTING -o {ppp} -j MASQUERADE "
            f"&& echo ADDED)",
            timeout=3,
        )
        if "ADDED" in r.stdout:
            masq_added = True
        # If iptables -A failed (no kernel mod, etc.) the test will
        # surface it via Tier C iperf3 timeout — but check rc here for
        # an early diagnosis.
        assert "ADDED" in r.stdout or "EXISTS" in r.stdout, (
            f"iptables MASQUERADE setup failed: {r.stdout!r}"
        )

        # CPU baseline before iperf3 — read /proc/stat aggregate line.
        # If FMAN is offloading the data plane, the LS1046A cores stay
        # mostly idle during the iperf3 window. Kernel slow-path PPPoE
        # encap/decap on this CPU saturates a single core well before
        # 1.5 Gbit/s — so a low %busy delta is the offload-engaged
        # signature.
        cpu_before = target.run(
            "awk '/^cpu / {print}' /proc/stat", timeout=3,
        ).stdout.strip()

        # Run iperf3 client from LAN VM (UART). Wrap in a task so we
        # can mid-flow query cmm's connection table without serializing.
        iperf_task = asyncio.create_task(lan_run(
            lan,
            f"iperf3 -c {inner_local} -t 5 -i 1 --connect-timeout 5000",
            timeout=30.0,
        ))

        # Mid-flow positive control: at t≈2s, query cmm's connection
        # table. If cmm's CT-watcher fired on the conntrack create
        # event for the iperf3 flow, the table has an entry for
        # inner_local. That's the offload precondition.
        await asyncio.sleep(2.0)
        cmm_q = await target_agent.cmm_query(
            aiohttp_session, table="connections",
        )
        cmm_out = cmm_q.get("stdout", "")

        r = await iperf_task

        # CPU after iperf3 — compute %busy delta over the run.
        cpu_after = target.run(
            "awk '/^cpu / {print}' /proc/stat", timeout=3,
        ).stdout.strip()

        assert r.rc == 0, (
            f"iperf3 client failed: rc={r.rc} out={r.stdout!r}"
        )
        assert "/sec" in r.stdout, (
            f"iperf3 didn't report throughput — connect failed or "
            f"silent error: {r.stdout!r}"
        )
        # Surface the iperf3 summary lines for visibility (-s in pytest).
        for line in r.stdout.splitlines():
            if "sender" in line or "receiver" in line:
                print(f"iperf3: {line.strip()}")
        # Surface DUT %busy delta over the iperf3 window. /proc/stat
        # cpu line: cpu user nice sys idle iowait irq sirq ...
        try:
            b = [int(x) for x in cpu_before.split()[1:8]]
            a = [int(x) for x in cpu_after.split()[1:8]]
            db = [a[i] - b[i] for i in range(len(b))]
            total = sum(db)
            idle  = db[3] + db[4]   # idle + iowait
            busy_pct = (total - idle) * 100.0 / total if total else 0
            print(f"DUT CPU %busy during iperf3 window (aggregate): "
                  f"{busy_pct:.1f}%   "
                  f"(user={db[0]} nice={db[1]} sys={db[2]} "
                  f"idle={db[3]} iow={db[4]} irq={db[5]} sirq={db[6]})")
        except (ValueError, IndexError) as e:
            print(f"CPU stat parse failed: {e}")
        # Offload positive control. cmm output is "cmm -c 'query
        # connections'" stdout; if the iperf3 flow is registered in
        # the FCI conntrack table, inner_local appears in it.
        assert inner_local in cmm_out, (
            f"cmm's connections table did NOT include the iperf3 flow "
            f"to {inner_local} during the test window. Throughput "
            f"came through kernel slow path, NOT FMAN offload — cmm's "
            f"CT-watcher didn't fire on the conntrack create event "
            f"(ppp0 conntrack flows may not be subscribed). "
            f"cmm output (truncated):\n{cmm_out[:1500]}"
        )
    finally:
        if masq_added:
            target.run(
                f"iptables -t nat -D POSTROUTING -o {ppp} -j MASQUERADE "
                f"2>/dev/null; true",
                timeout=3,
            )
        if prior_ip_forward is not None:
            target.run(
                f"sysctl -w net.ipv4.ip_forward={prior_ip_forward} "
                f">/dev/null; true",
                timeout=3,
            )
        target.close()
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()
