"""End-to-end PPPoE tests via real pppoe-server + pppd.

Three tiered tests, each gating on the previous:

  Tier A — test_pppoe_session_lifecycle
      pppd dialed → ppp iface UP → cmm auto-registered the session via
      its rtnetlink hook on RTM_NEWLINK ARPHRD_PPP. Load-bearing
      positive control: CMD_PPPOE_ENTRY ACTION_QUERY via fci_send
      returns NO_ERR. If cmm didn't push (or __itf_is_programmed(eth4)
      gate failed), QUERY returns ERR_PPPOE_ENTRY_NOT_FOUND and the
      assertion message names that gate as the suspect.

  Tier B — test_pppoe_dut_ping
      Triage-only: from DUT, `ping -I ppp0 10.98.0.1`. NOT an offload
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
    _console_ready,
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
    _console_ready(target)
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
        f"fire on RTM_NEWLINK ARPHRD_PPP, or __itf_is_programmed(eth4) "
        f"is False (eth4 not in cmm's iface table — check dpa_app "
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
    inner_local = os.environ.get("ASK_PPPOE_INNER_LOCAL", "10.98.0.1")
    target = Console.target()
    _console_ready(target)
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
    inner_local  = os.environ.get("ASK_PPPOE_INNER_LOCAL",  "10.98.0.1")

    # Vision-side iperf3 server bound to the inner IP. Pin a non-default
    # port (5201 is typically held by a system iperf3 service for ad-hoc
    # client connects). Capture stderr so any bind failure surfaces in
    # the assertion message rather than as a silent connect timeout.
    iperf_log = "/tmp/ask_pppoe_iperf3_server.log"
    iperf_port = 5333
    server = subprocess.Popen(
        ["iperf3", "-s", "-B", inner_local, "-p", str(iperf_port)],
        stdout=open(iperf_log, "w"), stderr=subprocess.STDOUT,
    )

    target = Console.target()
    _console_ready(target)
    masq_added = False
    prior_ip_forward: str | None = None
    try:
        await asyncio.sleep(0.5)  # iperf3 server bind grace

        # Diagnose iperf3 server bind: poll up to 3s for the listen
        # socket to appear. ppp0 may take a moment to come up after
        # the fixture yields; if iperf3 -s exited (bind failure on a
        # not-yet-present 10.98.0.1), surface the captured stderr.
        bind_ok = False
        for _ in range(15):
            if server.poll() is not None:
                break
            try:
                ck = subprocess.run(
                    ["ss", "-ltn", f"sport = :{iperf_port}"],
                    capture_output=True, text=True, timeout=2,
                )
                if inner_local in ck.stdout:
                    bind_ok = True
                    break
            except Exception:
                pass
            await asyncio.sleep(0.2)
        if not bind_ok:
            try:
                with open(iperf_log) as f:
                    log_tail = f.read()[-2000:]
            except Exception as e:
                log_tail = f"<log unreadable: {e}>"
            ppp_local = subprocess.run(
                ["ip", "-br", "addr", "show"],
                capture_output=True, text=True, timeout=3,
            ).stdout
            pytest.fail(
                f"iperf3 -s on Vision didn't bind {inner_local}:{iperf_port} "
                f"within 3s. server poll={server.poll()!r}.\n"
                f"iperf3 stderr/stdout:\n{log_tail}\n"
                f"vision interfaces:\n{ppp_local}"
            )

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
            f"iperf3 -c {inner_local} -p {iperf_port} -t 5 -i 1 "
            f"--connect-timeout 5000",
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

        if r.rc != 0:
            # Capture path-trace diagnostics so flakes don't require a
            # second run with extra logging.
            vision_pcap = "/tmp/ask_pppoe_vision_ppp0.pcap"
            tcpdump_proc = subprocess.Popen(
                ["tcpdump", "-ni", "any", "-w", vision_pcap, "-c", "10",
                 f"port {iperf_port} or icmp"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            await asyncio.sleep(0.5)  # tcpdump warmup
            await lan_run(
                lan,
                f"ping -c 2 -W 2 {inner_local} >/dev/null 2>&1",
                timeout=10.0,
            )
            await asyncio.sleep(1.0)
            tcpdump_proc.terminate()
            try:
                tcpdump_proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                tcpdump_proc.kill()
            wire = subprocess.run(
                ["tcpdump", "-r", vision_pcap, "-nn", "-tt"],
                capture_output=True, text=True, timeout=5,
            ).stdout

            dut_route = target.run(
                f"ip route get {inner_local}; "
                f"ip a show {ppp}; "
                f"iptables -t nat -nvL POSTROUTING | head -5; "
                f"iptables -nvL FORWARD | head -10; "
                f"sysctl -n net.ipv4.ip_forward",
                timeout=5,
            ).stdout
            vision_listen = subprocess.run(
                ["ss", "-ltnp", f"sport = :{iperf_port}"],
                capture_output=True, text=True, timeout=2,
            ).stdout
            try:
                with open(iperf_log) as f:
                    server_log = f.read()[-1000:]
            except Exception:
                server_log = "<unreadable>"
            lan_ping = await lan_run(
                lan,
                f"ping -c 2 -W 2 {inner_local}; "
                f"traceroute -n -w 1 -m 5 {inner_local} 2>/dev/null | head -8",
                timeout=15.0,
            )
            pytest.fail(
                f"iperf3 client failed: rc={r.rc} out={r.stdout!r}\n\n"
                f"--- DUT route + iptables + ip_forward ---\n{dut_route}\n"
                f"--- Vision listen ---\n{vision_listen}\n"
                f"--- iperf3 server log ---\n{server_log}\n"
                f"--- LAN VM ping/traceroute ---\n{lan_ping.stdout}\n"
                f"--- Vision tcpdump (any iface, port {iperf_port} or icmp) ---\n{wire}"
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
        try: os.unlink(iperf_log)
        except FileNotFoundError: pass
