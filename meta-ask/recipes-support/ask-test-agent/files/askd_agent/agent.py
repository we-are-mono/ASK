"""aiohttp HTTP/JSON agent for the ASK test harness.

Exposes the minimum surface the orchestrator needs. Endpoints are stateless
apart from a per-capture cursor dict that lives in app state.
"""

from __future__ import annotations

import asyncio
import os
import platform
import secrets
import socket
import struct
import subprocess
from pathlib import Path

from aiohttp import web

from . import __version__, counters, dmesg

KMEMLEAK_PATH = Path("/sys/kernel/debug/kmemleak")

# NETLINK_FF is the protocol number FCI uses (see fci/fci.h:44,
# fci/lib/src/libfci.c:27). Matches the kernel uapi header where the
# ASK patch bundle installs NETLINK_FF=30.
NETLINK_FF = 30

# struct nlmsghdr is 16 bytes on all 64-bit Linux: u32 len, u16 type,
# u16 flags, u32 seq, u32 pid.
_NLMSGHDR_SIZE = 16

# Whitelist of cmm -c query sub-commands the orchestrator is allowed to run.
# Keeps the HTTP surface from becoming an RCE by bounding exactly what cmm
# invocations are accepted. Extend as we add more protocol coverage.
CMM_QUERY_TABLES = {
    "connections",          # IPv4 conntrack
    "v6-connections",       # IPv6 conntrack
    "tunnels",
    "vlan",
    "pppoe",
    "ipsec-sa",
    "mcast",
    "bridge",
}


def _new_capture_id() -> str:
    return secrets.token_hex(8)


async def health(request: web.Request) -> web.Response:
    return web.json_response({
        "ok": True,
        "version": __version__,
        "host": platform.node(),
        "uptime_s": _read_uptime(),
    })


def _read_uptime() -> float:
    try:
        return float(Path("/proc/uptime").read_text().split()[0])
    except (OSError, ValueError):
        return 0.0


async def counters_get(request: web.Request) -> web.Response:
    ifaces = request.query.getall("iface", []) or ["eth3", "eth4"]
    return web.json_response(counters.snapshot(ifaces))


async def capture_start(request: web.Request) -> web.Response:
    ifaces = (await _maybe_json(request)).get("ifaces") or ["eth3", "eth4"]
    cap_id = _new_capture_id()
    request.app["captures"][cap_id] = {
        "kmsg_cursor": dmesg.read_kmsg_seq(),
        "counters": counters.snapshot(ifaces),
        "ifaces": ifaces,
    }
    return web.json_response({"capture_id": cap_id})


async def capture_stop(request: web.Request) -> web.Response:
    cap_id = request.match_info["cap_id"]
    cap = request.app["captures"].pop(cap_id, None)
    if cap is None:
        return web.json_response({"error": "unknown capture_id"}, status=404)
    new_cursor, new_lines = dmesg.read_since(cap["kmsg_cursor"])
    after = counters.snapshot(cap["ifaces"])
    splats = dmesg.has_splat(new_lines)
    return web.json_response({
        "dmesg": new_lines,
        "splats": splats,
        "kmsg_cursor_end": new_cursor,
        "counters_delta": counters.diff_numeric(cap["counters"], after),
    })


async def dmesg_delta(request: web.Request) -> web.Response:
    body = await _maybe_json(request)
    cursor = body.get("cursor")
    new_cursor, lines = dmesg.read_since(cursor)
    return web.json_response({
        "cursor": new_cursor,
        "lines": lines,
        "splats": dmesg.has_splat(lines),
    })


async def cmm_query(request: web.Request) -> web.Response:
    """Run `cmm -c "query <table>"` and return stdout/stderr/rc.

    No parsing yet — orchestrator handles output. Table name is whitelisted
    so an orchestrator bug can't get arbitrary shell out of this endpoint.
    """
    body = await _maybe_json(request)
    table = body.get("table", "connections")
    if table not in CMM_QUERY_TABLES:
        return web.json_response(
            {"error": f"unknown table {table!r}; allowed: {sorted(CMM_QUERY_TABLES)}"},
            status=400,
        )
    try:
        # Use argv form (no shell=True) — no injection risk even before the
        # whitelist, and cmm -c takes the query as a single argument.
        r = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: subprocess.run(
                ["cmm", "-c", f"query {table}"],
                capture_output=True, text=True, timeout=5, check=False,
            ),
        )
    except FileNotFoundError:
        return web.json_response({"error": "cmm not installed"}, status=501)
    except subprocess.TimeoutExpired:
        return web.json_response({"error": "cmm timed out"}, status=504)
    return web.json_response({
        "table":  table,
        "rc":     r.returncode,
        "stdout": r.stdout,
        "stderr": r.stderr,
    })


def _netlink_send_sync(
    protocol: int,
    body: bytes,
    nlmsg_len_override: int | None,
    nlmsg_type: int,
    nlmsg_flags: int,
    timeout_s: float,
) -> dict:
    """Send a raw netlink message, return the raw reply + parse hints.

    `body` is everything after the nlmsghdr — the message payload the
    kernel's input handler sees. By default the nlmsghdr's nlmsg_len
    matches the actual on-wire bytes (16 + len(body)); tests can lie
    via `nlmsg_len_override` to probe handlers' own length validation
    (e.g. C2 fix in fci.c checks skb->len vs nlmsg_len).
    """
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, protocol)
    try:
        sock.bind((0, 0))
        sock.settimeout(timeout_s)

        real_len   = _NLMSGHDR_SIZE + len(body)
        header_len = real_len if nlmsg_len_override is None else nlmsg_len_override
        # Header fields: u32 len, u16 type, u16 flags, u32 seq, u32 pid
        nlh = struct.pack(
            "=IHHII", header_len & 0xFFFFFFFF,
            nlmsg_type & 0xFFFF, nlmsg_flags & 0xFFFF,
            1, 0,
        )
        sock.send(nlh + body)

        try:
            reply = sock.recv(8192)
        except socket.timeout:
            reply = b""

        out: dict = {"sent_bytes": real_len, "reply_hex": reply.hex()}
        if len(reply) >= _NLMSGHDR_SIZE:
            reply_body = reply[_NLMSGHDR_SIZE:]
            out["body_hex"] = reply_body.hex()
        return out
    finally:
        sock.close()


_FAILSLAB_DIR = Path("/sys/kernel/debug/failslab")


def _arm_failslab(times: int) -> None:
    """Configure failslab to fault the next `times` kmalloc calls that come
    from a task with /proc/self/make-it-fail set. Probability 100 so every
    candidate inside the window deterministically fails. Callers must hold
    the task-filter context alone (typically via fork) — arming in the
    shared agent process would poison all subsequent allocations."""
    (_FAILSLAB_DIR / "task-filter").write_text("Y\n")
    (_FAILSLAB_DIR / "probability").write_text("100\n")
    (_FAILSLAB_DIR / "times").write_text(f"{times}\n")
    # `space` is a byte-budget countdown; zero it so `times` is the only gate.
    try:
        (_FAILSLAB_DIR / "space").write_text("0\n")
    except OSError:
        pass
    Path("/proc/self/make-it-fail").write_text("1\n")


def _disarm_failslab() -> None:
    """Best-effort disarm. Call before the child exits so global state
    (probability, times) doesn't linger for the next test."""
    try:
        (_FAILSLAB_DIR / "probability").write_text("0\n")
    except OSError:
        pass
    try:
        Path("/proc/self/make-it-fail").write_text("0\n")
    except OSError:
        pass


def _netlink_send_failslab(
    protocol: int,
    body: bytes,
    nlmsg_len_override: int | None,
    nlmsg_type: int,
    nlmsg_flags: int,
    timeout_s: float,
    failslab_times: int,
) -> dict:
    """Fork a child, open the netlink socket there, arm failslab scoped to
    the child only, send the FCI message, then disarm. The fork isolates
    make-it-fail from the parent agent — otherwise arming would fault the
    agent's own kmallocs (aiohttp handlers, JSON serialization) and wedge
    the service.

    Arming *after* socket creation means the `times=N` counter is spent on
    kmallocs during the send/recv syscall path and whatever they call into
    (FCI inbound handler, cdx dispatcher, mcast handlers) — not on the
    bookkeeping overhead of opening the socket itself.
    """
    import pickle

    r_fd, w_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r_fd)
        result: dict = {}
        armed = False
        try:
            sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, protocol)
            sock.bind((0, 0))
            sock.settimeout(timeout_s)

            real_len   = _NLMSGHDR_SIZE + len(body)
            header_len = real_len if nlmsg_len_override is None else nlmsg_len_override
            nlh = struct.pack(
                "=IHHII", header_len & 0xFFFFFFFF,
                nlmsg_type & 0xFFFF, nlmsg_flags & 0xFFFF,
                1, 0,
            )
            msg = nlh + body

            _arm_failslab(failslab_times)
            armed = True

            send_err = None
            try:
                sock.send(msg)
            except OSError as e:
                send_err = f"send: errno={e.errno} {e.strerror}"

            reply = b""
            if send_err is None:
                try:
                    reply = sock.recv(8192)
                except socket.timeout:
                    reply = b""
                except OSError as e:
                    send_err = f"recv: errno={e.errno} {e.strerror}"

            # Disarm ASAP so the subsequent pickle/pipe write doesn't
            # also see faults.
            _disarm_failslab()
            armed = False

            result = {
                "sent_bytes":     real_len,
                "reply_hex":      reply.hex(),
                "failslab_times": failslab_times,
            }
            if send_err:
                result["send_error"] = send_err
            if len(reply) >= _NLMSGHDR_SIZE:
                result["body_hex"] = reply[_NLMSGHDR_SIZE:].hex()
            sock.close()
        except OSError as e:
            result = {"error": f"setup failed: errno={e.errno} {e.strerror}"}
        except Exception as e:
            result = {"error": f"{type(e).__name__}: {e}"}
        finally:
            if armed:
                # Exception between arm and explicit disarm — best effort.
                _disarm_failslab()
        try:
            os.write(w_fd, pickle.dumps(result))
        finally:
            os.close(w_fd)
            os._exit(0)

    os.close(w_fd)
    buf = b""
    try:
        while True:
            chunk = os.read(r_fd, 65536)
            if not chunk:
                break
            buf += chunk
    finally:
        os.close(r_fd)
    os.waitpid(pid, 0)
    try:
        return pickle.loads(buf)
    except Exception as e:
        return {"error": f"child produced no result: {e}"}


def _parse_fci_reply(result: dict) -> dict:
    """Overlay FCI_MSG interpretation on a generic netlink send result."""
    body_hex = result.get("body_hex", "")
    if not body_hex:
        return result
    body = bytes.fromhex(body_hex)
    if len(body) >= 4:
        result["fcode_echo"]   = int.from_bytes(body[0:2], "little")
        result["reply_length"] = int.from_bytes(body[2:4], "little")
    if len(body) >= 6:
        result["reply_rc"]    = int.from_bytes(body[4:6], "little")
        result["payload_hex"] = body[4:].hex()
    return result


async def fci_send(request: web.Request) -> web.Response:
    """POST {fcode, length, payload_hex, [nlmsg_len_override], [timeout_ms]}
    -> FCI kernel reply.

    Designed for fuzzing the A1 validator tables AND the C2 length-
    validation defense: pass `nlmsg_len_override` to lie about the
    netlink header's length field independent of the body bytes sent.
    """
    body = await _maybe_json(request)
    try:
        fcode   = int(body["fcode"])  & 0xFFFF
        length  = int(body["length"]) & 0xFFFF
        payload = bytes.fromhex(body.get("payload_hex", ""))
    except (KeyError, ValueError, TypeError) as e:
        return web.json_response(
            {"error": f"bad request: {e}"}, status=400,
        )
    nlmsg_len_override = body.get("nlmsg_len_override")
    timeout_s = float(body.get("timeout_ms", 500)) / 1000.0
    failslab_times = body.get("failslab_times")

    fci_body = struct.pack("<HH", fcode, length) + payload
    try:
        if failslab_times is None:
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                _netlink_send_sync,
                NETLINK_FF, fci_body, nlmsg_len_override, 0, 0, timeout_s,
            )
        else:
            # Fork-isolated path: failslab make-it-fail can only safely
            # target a throwaway child, otherwise the agent's own aiohttp
            # response path also faults and the service hangs.
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                _netlink_send_failslab,
                NETLINK_FF, fci_body, nlmsg_len_override, 0, 0, timeout_s,
                int(failslab_times),
            )
    except OSError as e:
        return web.json_response({"error": f"socket error: {e}"}, status=500)
    result = _parse_fci_reply(result)
    return web.json_response(result)


def _run_isolated(work, uid: int | None, timeout_s: float) -> dict:
    """Fork a subprocess, optionally drop to `uid`, call `work()`, pipe back
    a result dict. Used for ioctl + file-write endpoints that the orchestrator
    wants to run as an unprivileged user (G1 / H8).
    """
    import json
    import pickle

    r_fd, w_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r_fd)
        result: dict = {}
        try:
            if uid is not None:
                # setresgid before setresuid (reverse is forbidden when
                # dropping root — gid needs the privilege to change).
                os.setresgid(uid, uid, uid)
                os.setresuid(uid, uid, uid)
            result = work()
        except OSError as e:
            result = {"error": str(e), "errno": e.errno}
        except Exception as e:
            result = {"error": f"{type(e).__name__}: {e}"}
        try:
            os.write(w_fd, pickle.dumps(result))
        finally:
            os.close(w_fd)
            os._exit(0)
    os.close(w_fd)
    buf = b""
    try:
        while True:
            chunk = os.read(r_fd, 65536)
            if not chunk:
                break
            buf += chunk
    finally:
        os.close(r_fd)
    os.waitpid(pid, 0)
    try:
        return pickle.loads(buf)
    except Exception as e:
        return {"error": f"child produced no result: {e}; raw={buf!r}"}


def _ioctl_work(device: str, cmd: int, data_in: bytes) -> dict:
    import fcntl
    try:
        fd = os.open(device, os.O_RDWR)
    except OSError as e:
        return {"rc": -1, "errno": e.errno, "error": f"open: {e.strerror}"}
    try:
        buf = bytearray(data_in) if data_in else bytearray(0)
        try:
            rc = fcntl.ioctl(fd, cmd, buf, True) if data_in else fcntl.ioctl(fd, cmd, 0)
            return {"rc": int(rc), "errno": 0, "data_hex": bytes(buf).hex()}
        except OSError as e:
            return {"rc": -1, "errno": e.errno, "error": e.strerror}
    finally:
        os.close(fd)


async def ioctl_send(request: web.Request) -> web.Response:
    """POST {device, cmd, data_hex, [uid], [timeout_ms]} -> ioctl result.

    Used for capability / bounds testing of /dev/cdx_ctrl and friends.
    `uid` optionally drops to an unprivileged UID before the open/ioctl
    (for G1-style tests). `data_hex` is the input buffer passed to the
    kernel; on IOR/IOWR ioctls the kernel writes back into that buffer
    and it comes back as `data_hex` in the response.
    """
    body = await _maybe_json(request)
    try:
        device = body["device"]
        cmd    = int(body["cmd"])
        data   = bytes.fromhex(body.get("data_hex", ""))
    except (KeyError, ValueError, TypeError) as e:
        return web.json_response({"error": f"bad request: {e}"}, status=400)
    uid = body.get("uid")
    if uid is not None:
        uid = int(uid)
    timeout_s = float(body.get("timeout_ms", 1000)) / 1000.0

    def _work():
        return _ioctl_work(device, cmd, data)

    result = await asyncio.get_event_loop().run_in_executor(
        None, _run_isolated, _work, uid, timeout_s,
    )
    return web.json_response(result)


_EXEC_ARGV0_ALLOWED = {
    "ip", "ethtool", "iptables", "modprobe", "rmmod", "insmod",
    "sysctl", "conntrack", "bridge", "tcpdump",
}


async def exec_cmd(request: web.Request) -> web.Response:
    """POST {argv[], [timeout_ms]} -> {rc, stdout, stderr}.

    Used by test fixtures for net-config (ip link add, routes, iptables
    rules, etc.) that the DUT needs before and after a scenario. argv[0]
    is whitelisted to keep the surface from becoming arbitrary RCE — the
    agent still runs as root so the shell would inherit that.
    """
    body = await _maybe_json(request)
    argv = body.get("argv")
    if not isinstance(argv, list) or not argv:
        return web.json_response({"error": "argv must be non-empty list"}, status=400)
    if argv[0] not in _EXEC_ARGV0_ALLOWED:
        return web.json_response(
            {"error": f"argv[0]={argv[0]!r} not allowed; "
                     f"allowed: {sorted(_EXEC_ARGV0_ALLOWED)}"},
            status=400,
        )
    timeout_s = float(body.get("timeout_ms", 5000)) / 1000.0
    try:
        r = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: subprocess.run(
                argv, capture_output=True, text=True,
                timeout=timeout_s, check=False,
            ),
        )
    except FileNotFoundError:
        return web.json_response({"error": f"{argv[0]} not installed"}, status=501)
    except subprocess.TimeoutExpired:
        return web.json_response({"error": "exec timed out"}, status=504)
    return web.json_response({
        "argv":   argv,
        "rc":     r.returncode,
        "stdout": r.stdout,
        "stderr": r.stderr,
    })


async def fs_write(request: web.Request) -> web.Response:
    """POST {path, content, [uid], [timeout_ms]} -> write attempt result.

    Used for sysctl / /proc / /sys write tests that care about capability
    enforcement (e.g. H8: abm_sysctl_l3_filtering rejects non-CAP_NET_ADMIN).
    """
    body = await _maybe_json(request)
    try:
        path = body["path"]
        content = body.get("content", "")
    except (KeyError, TypeError) as e:
        return web.json_response({"error": f"bad request: {e}"}, status=400)
    uid = body.get("uid")
    if uid is not None:
        uid = int(uid)
    timeout_s = float(body.get("timeout_ms", 1000)) / 1000.0

    data = content.encode() if isinstance(content, str) else bytes(content)

    def _work():
        try:
            with open(path, "wb") as f:
                n = f.write(data)
            return {"rc": int(n), "errno": 0}
        except OSError as e:
            return {"rc": -1, "errno": e.errno, "error": e.strerror}

    result = await asyncio.get_event_loop().run_in_executor(
        None, _run_isolated, _work, uid, timeout_s,
    )
    return web.json_response(result)


async def netlink_send(request: web.Request) -> web.Response:
    """POST {protocol, body_hex, [nlmsg_type, nlmsg_flags,
                                  nlmsg_len_override, timeout_ms]}
    -> raw kernel reply.

    Lower-level than /fci/send: the agent prepends a netlink header but
    everything else is the caller's bytes verbatim. Use this to target
    netlink protocols that aren't FCI (e.g. NETLINK_L2FLOW=33 for
    auto_bridge) or to probe layers that wrap FCI with their own
    structure (like libfci's nlmsg_len trickery from the C2 write-up).
    """
    body = await _maybe_json(request)
    try:
        protocol = int(body["protocol"])
        msg = bytes.fromhex(body.get("body_hex", ""))
    except (KeyError, ValueError, TypeError) as e:
        return web.json_response({"error": f"bad request: {e}"}, status=400)
    nlmsg_type  = int(body.get("nlmsg_type", 0))
    nlmsg_flags = int(body.get("nlmsg_flags", 0))
    nlmsg_len_override = body.get("nlmsg_len_override")
    timeout_s = float(body.get("timeout_ms", 500)) / 1000.0
    try:
        result = await asyncio.get_event_loop().run_in_executor(
            None,
            _netlink_send_sync,
            protocol, msg, nlmsg_len_override,
            nlmsg_type, nlmsg_flags, timeout_s,
        )
    except OSError as e:
        return web.json_response({"error": f"socket error: {e}"}, status=500)
    return web.json_response(result)


def _kmemleak_split(report: str) -> list[str]:
    """Split a kmemleak report into per-leak blocks.

    Each leak block starts with "unreferenced object" and runs until
    the next "unreferenced object" or end of text. Empty strings
    between boundaries are dropped.
    """
    blocks: list[str] = []
    current: list[str] = []
    for line in report.splitlines(keepends=True):
        if line.startswith("unreferenced object"):
            if current:
                blocks.append("".join(current))
            current = [line]
        elif current:
            current.append(line)
    if current:
        blocks.append("".join(current))
    return blocks


def _kmemleak_filter(blocks: list[str], needles: list[str]) -> list[str]:
    """Keep leak blocks whose trace text contains any of `needles`."""
    if not needles:
        return blocks
    return [b for b in blocks if any(n in b for n in needles)]


async def kmemleak_scan(request: web.Request) -> web.Response:
    """GET ?filter=cdx_,fci_,abm_ -> filtered kmemleak report.

    Without `filter`, returns the full report (all ~16k baseline DPAA
    false-positives included) — backward-compatible with callers that
    don't care about noise. With `filter`, returns only the leak blocks
    whose trace text contains at least one of the comma-separated
    substrings. Pair with POST /kmemleak-clear to get a true since-
    cursor delta: clear at test start, scan with filter at test end,
    assert blocks == [].
    """
    if not KMEMLEAK_PATH.exists():
        return web.json_response({"error": "kmemleak not available"}, status=501)
    try:
        KMEMLEAK_PATH.write_text("scan\n")
    except OSError as e:
        return web.json_response({"error": f"scan write failed: {e}"}, status=500)
    # kmemleak's scanner is async in kernel; wait a bit for results to settle.
    await asyncio.sleep(2.0)
    try:
        report = KMEMLEAK_PATH.read_text()
    except OSError as e:
        return web.json_response({"error": f"read failed: {e}"}, status=500)
    filter_raw = request.query.get("filter", "")
    needles = [s for s in filter_raw.split(",") if s] if filter_raw else []
    if needles:
        blocks = _kmemleak_filter(_kmemleak_split(report), needles)
        return web.json_response({
            "report": "".join(blocks),
            "leak_count": len(blocks),
            "filter": needles,
        })
    return web.json_response({
        "report": report,
        "leak_count": report.count("unreferenced object"),
    })


async def kmemleak_clear(request: web.Request) -> web.Response:
    """POST -> mark all currently-reported kmemleak leaks as seen.

    Writes "scan" first, waits a beat for the scanner to classify all
    currently-unreferenced objects (`clear` only marks the
    already-classified ones; boot-time allocations that the kernel's
    own background scanner hasn't swept yet would otherwise slip past
    the cursor and appear as "new" leaks on the next scan), then
    writes "clear" to /sys/kernel/debug/kmemleak. Subsequent scans
    (and reads of the file) only show leaks detected after this call.
    This is the cursor primitive for per-test leak deltas: the 16k
    DPAA false-positive baseline is erased once and the test window
    starts clean.
    """
    if not KMEMLEAK_PATH.exists():
        return web.json_response({"error": "kmemleak not available"}, status=501)
    # The write to "scan" is synchronous — the kernel walks the heap
    # before returning. Necessary to run this BEFORE "clear": `clear`
    # only sets OBJECT_REPORTED on allocations that are already marked
    # UNREFERENCED, and the in-kernel background scanner runs on a
    # 10-minute cadence. Without a forced scan first, fresh boot-time
    # allocations that haven't been classified yet slip past the
    # cursor and reappear as "new" leaks on the very next scan.
    # Offload to a thread so we don't block the event loop during the
    # 30-60s first-boot heap walk.
    def _scan_then_clear() -> None:
        KMEMLEAK_PATH.write_text("scan\n")
        KMEMLEAK_PATH.write_text("clear\n")
    try:
        await asyncio.get_event_loop().run_in_executor(None, _scan_then_clear)
    except OSError as e:
        return web.json_response({"error": f"scan/clear failed: {e}"}, status=500)
    return web.json_response({"ok": True})


async def _maybe_json(request: web.Request) -> dict:
    if request.content_length and request.content_length > 0:
        try:
            return await request.json()
        except Exception:
            return {}
    return {}


# ASK loadable-module stack. Listed in rmmod order (top-of-stack first):
# auto_bridge depends on fci which depends on cdx, so unloading goes
# auto_bridge -> fci -> cdx and modprobing goes in reverse.
_ASK_MODULES = ("auto_bridge", "fci", "cdx")


def _module_reload_init_work(target: str, failslab_times: int) -> dict:
    """Inside a fork: configure failslab if requested, then modprobe.

    Targeting subtlety: failslab's `times` counter is global, but
    fires only on tasks tagged via /proc/<pid>/make-it-fail. If we
    tagged this child (the work-runner), our own pre-modprobe kmallocs
    (Python interpreter, subprocess.run scaffolding, fork-for-exec)
    would consume the budget before modprobe even starts. So we
    configure failslab globally here but defer the per-task tag to
    `preexec_fn`, which runs in the modprobe child *after* fork but
    *before* exec — every kmalloc from then on counts against `times`.

    Even with this targeting, exec setup + modprobe userspace + the
    finit_module syscall path all still happen before the module's
    init function runs, so the first ~dozens of fault budgets are
    spent on scaffolding. Sweeping `failslab_times` over a range that
    extends past that scaffolding count is what gets the fault into
    the actual init body.
    """
    armed = False
    try:
        if failslab_times > 0:
            # Configure global failslab knobs but don't tag ourselves.
            (_FAILSLAB_DIR / "task-filter").write_text("Y\n")
            (_FAILSLAB_DIR / "probability").write_text("100\n")
            (_FAILSLAB_DIR / "times").write_text(f"{failslab_times}\n")
            try:
                (_FAILSLAB_DIR / "space").write_text("0\n")
            except OSError:
                pass
            armed = True

            def _tag_modprobe_child():
                # Runs in the modprobe child between fork and exec.
                # No kmallocs in this Python callback are an issue —
                # they happen before the tag is applied. The tag
                # affects only allocations after the write below.
                Path("/proc/self/make-it-fail").write_text("1\n")
        else:
            _tag_modprobe_child = None

        proc = subprocess.run(
            ["modprobe", target],
            capture_output=True, timeout=15,
            preexec_fn=_tag_modprobe_child,
        )
        return {
            "init_rc": proc.returncode,
            "init_stderr": proc.stderr.decode(errors="replace").strip(),
            "init_stdout": proc.stdout.decode(errors="replace").strip(),
        }
    except subprocess.TimeoutExpired:
        return {"init_rc": -1, "init_stderr": "modprobe timeout"}
    except Exception as e:
        return {"init_rc": -1, "init_stderr": f"{type(e).__name__}: {e}"}
    finally:
        if armed:
            _disarm_failslab()


async def module_reload(request: web.Request) -> web.Response:
    """POST {target, [failslab_times], [timeout_ms]} -> reload result.

    Tears down the ASK module stack from auto_bridge down to (and
    including) `target`, modprobes `target` with optional failslab
    arming during init, then restores the rest of the stack so the
    system isn't left half-loaded for the next test.

    Used by A3a-e fault-injection tests to probe init-path leak/UAF
    behaviour. failslab=0 just exercises the rmmod/modprobe round-trip
    (useful as a baseline / smoke).
    """
    body = await _maybe_json(request)
    target = body.get("target")
    if target not in _ASK_MODULES:
        return web.json_response(
            {"error": f"target must be one of {list(_ASK_MODULES)}"},
            status=400,
        )
    failslab_times = int(body.get("failslab_times", 0))
    timeout_s = float(body.get("timeout_ms", 30000)) / 1000.0

    # Tear down stack from auto_bridge down to (and including) target.
    rmmod_log: list[dict] = []
    for mod in _ASK_MODULES:
        proc = subprocess.run(["rmmod", mod], capture_output=True)
        rmmod_log.append({
            "module": mod,
            "rc": proc.returncode,
            "stderr": proc.stderr.decode(errors="replace").strip(),
        })
        if mod == target:
            break

    # Modprobe target with optional failslab — isolated child.
    def _work():
        return _module_reload_init_work(target, failslab_times)
    init_result = await asyncio.get_event_loop().run_in_executor(
        None, _run_isolated, _work, None, timeout_s,
    )

    # Restore the rest of the stack regardless of init outcome.
    restore: list[dict] = []
    order = list(reversed(_ASK_MODULES))
    idx = order.index(target)
    for mod in order[idx:]:
        proc = subprocess.run(["modprobe", mod], capture_output=True)
        restore.append({
            "module": mod,
            "rc": proc.returncode,
            "stderr": proc.stderr.decode(errors="replace").strip(),
        })

    return web.json_response({
        "target": target,
        "failslab_times": failslab_times,
        "rmmod_log": rmmod_log,
        "init_result": init_result,
        "restore": restore,
    })


def build_app() -> web.Application:
    app = web.Application()
    app["captures"] = {}
    app.router.add_get("/health",            health)
    app.router.add_get("/counters",          counters_get)
    app.router.add_post("/capture-start",    capture_start)
    app.router.add_post("/capture-stop/{cap_id}", capture_stop)
    app.router.add_post("/dmesg-delta",      dmesg_delta)
    app.router.add_get("/kmemleak-scan",     kmemleak_scan)
    app.router.add_post("/kmemleak-clear",   kmemleak_clear)
    app.router.add_post("/cmm/query",        cmm_query)
    app.router.add_post("/fci/send",         fci_send)
    app.router.add_post("/netlink/send",     netlink_send)
    app.router.add_post("/ioctl/send",       ioctl_send)
    app.router.add_post("/fs/write",         fs_write)
    app.router.add_post("/exec",             exec_cmd)
    app.router.add_post("/module/reload",    module_reload)
    return app


def main() -> None:
    host = os.environ.get("ASKD_HOST", "0.0.0.0")
    port = int(os.environ.get("ASKD_PORT", "9110"))
    web.run_app(build_app(), host=host, port=port, access_log=None)


if __name__ == "__main__":
    main()
