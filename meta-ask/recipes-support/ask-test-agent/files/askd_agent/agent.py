"""aiohttp HTTP/JSON agent for the ASK test harness.

Exposes the minimum surface the orchestrator needs. Endpoints are stateless
apart from a per-capture cursor dict that lives in app state.
"""

from __future__ import annotations

import asyncio
import errno
import os
import platform
import re
import secrets
import select
import signal
import socket
import struct
import subprocess
import threading
import time
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
    "mc4",                  # IPv4 multicast group entries (FCI mc4)
    "mc6",                  # IPv6 multicast group entries (FCI mc6)
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
        # Capture as bytes (text=False) and decode with errors='replace':
        # cmm's query output occasionally embeds non-UTF-8 bytes (binary
        # fields, raw memory in name buffers), which under text=True makes
        # subprocess raise UnicodeDecodeError mid-_communicate and the
        # handler returns 500 to the caller.
        r = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: subprocess.run(
                ["cmm", "-c", f"query {table}"],
                capture_output=True, timeout=5, check=False,
            ),
        )
    except FileNotFoundError:
        return web.json_response({"error": "cmm not installed"}, status=501)
    except subprocess.TimeoutExpired:
        return web.json_response({"error": "cmm timed out"}, status=504)
    return web.json_response({
        "table":  table,
        "rc":     r.returncode,
        "stdout": r.stdout.decode("utf-8", errors="replace"),
        "stderr": r.stderr.decode("utf-8", errors="replace"),
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


def _arm_failslab(n: int) -> None:
    """Configure failslab to fault exactly the Nth kmalloc made by the
    current task.

    Mechanism: per-task `/proc/self/fail-nth` is the only correct primitive
    for surgical fault injection here. Unlike `times`/`probability` (global
    counters that drain on incidental allocations), fail_nth is decremented
    only by the current task's kmallocs and bypasses all other failslab
    gates (probability, task-filter, times, interval) — see
    lib/fault-inject.c:should_fail_ex.

    The wrapper `should_failslab` still filters on `ignore-gfp-wait` BEFORE
    reaching should_fail_ex, so GFP_KERNEL allocations would be exempt
    under the kernel default (Y). Flip it off here so cdx handler kmallocs
    (all GFP_KERNEL) become eligible.
    """
    try:
        (_FAILSLAB_DIR / "ignore-gfp-wait").write_text("N\n")
    except OSError:
        pass
    Path("/proc/self/fail-nth").write_text(f"{n}\n")


def _disarm_failslab() -> None:
    """Best-effort disarm. Call before the child exits so the global
    `ignore-gfp-wait` knob is back at the kernel default for the next test
    (a left-on `N` would expose other tests to spurious GFP_KERNEL faults
    via any latent fail-nth on long-running daemons)."""
    try:
        Path("/proc/self/fail-nth").write_text("0\n")
    except OSError:
        pass
    try:
        (_FAILSLAB_DIR / "ignore-gfp-wait").write_text("Y\n")
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
    """POST {fcode, length, payload_hex, [nlmsg_len_override], [timeout_ms],
             [uid], [userns]}
    -> FCI kernel reply.

    Designed for fuzzing the A1 validator tables AND the C2 length-
    validation defense: pass `nlmsg_len_override` to lie about the
    netlink header's length field independent of the body bytes sent.

    `uid` / `userns` fork a child that drops privilege before opening
    the netlink socket (the in-kernel netlink_capable gate checks the
    socket opener's credentials), for capability-gate tests.
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
    uid = body.get("uid")
    if uid is not None:
        uid = int(uid)
    userns = bool(body.get("userns", False))

    fci_body = struct.pack("<HH", fcode, length) + payload
    try:
        if uid is not None or userns:
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: _run_isolated(
                    lambda: _netlink_send_sync(
                        NETLINK_FF, fci_body, nlmsg_len_override,
                        0, 0, timeout_s,
                    ),
                    uid, timeout_s, userns=userns,
                ),
            )
        elif failslab_times is None:
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


_CLONE_NEWUSER = 0x10000000


def _enter_unmapped_userns() -> None:
    """Create a new user namespace with no uid/gid mappings.

    With no mapping, all uids in the namespace map to /proc/sys/kernel/
    overflowuid (typically 65534) and capable() against init_user_ns
    returns false — exactly what the unmapped-userns capability-gate
    test wants to assert on a CAP_NET_ADMIN-gated ioctl.
    """
    os.unshare(_CLONE_NEWUSER)


def _run_isolated(
    work, uid: int | None, timeout_s: float, *, userns: bool = False,
) -> dict:
    """Fork a subprocess, optionally drop to `uid` and/or enter an
    unmapped new userns, call `work()`, pipe back a result dict.
    """
    import pickle

    r_fd, w_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r_fd)
        result: dict = {}
        try:
            if userns:
                _enter_unmapped_userns()
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
    deadline = time.monotonic() + timeout_s if timeout_s and timeout_s > 0 else None
    timed_out = False
    try:
        while True:
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([r_fd], [], [], remaining)[0]:
                    timed_out = True
                    break
            chunk = os.read(r_fd, 65536)
            if not chunk:
                break
            buf += chunk
    finally:
        os.close(r_fd)
    if timed_out:
        # Child wedged (e.g. stuck in a kernel call) — kill so we neither
        # block the agent forever nor leak a zombie past the waitpid.
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    os.waitpid(pid, 0)
    if timed_out:
        return {"error": f"timed out after {timeout_s}s", "errno": errno.ETIMEDOUT}
    try:
        return pickle.loads(buf)
    except Exception as e:
        return {"error": f"child produced no result: {e}; raw={buf!r}"}


# capset() ABI — mirror of <linux/capability.h>. Lets us drop a single
# capability from the effective+permitted+inheritable sets between the
# privileged open of /dev/cdx_ctrl and the ioctl, so the dispatcher's
# capable(CAP_NET_ADMIN) check sees a stripped credential set.
_LINUX_CAPABILITY_VERSION_3 = 0x20080522
_CAP_NET_ADMIN = 12


class _CapHeader(__import__("ctypes").Structure):
    import ctypes as _ct
    _fields_ = [("version", _ct.c_uint32), ("pid", _ct.c_int)]


class _CapData(__import__("ctypes").Structure):
    import ctypes as _ct
    _fields_ = [
        ("effective",   _ct.c_uint32),
        ("permitted",   _ct.c_uint32),
        ("inheritable", _ct.c_uint32),
    ]


def _drop_cap_net_admin() -> None:
    import ctypes
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.capget.argtypes = [ctypes.POINTER(_CapHeader), ctypes.POINTER(_CapData)]
    libc.capget.restype  = ctypes.c_int
    libc.capset.argtypes = [ctypes.POINTER(_CapHeader), ctypes.POINTER(_CapData)]
    libc.capset.restype  = ctypes.c_int

    hdr = _CapHeader(version=_LINUX_CAPABILITY_VERSION_3, pid=0)
    data = (_CapData * 2)()
    if libc.capget(ctypes.byref(hdr), data) != 0:
        e = ctypes.get_errno()
        raise OSError(e, f"capget: {os.strerror(e)}")
    mask = ~(1 << _CAP_NET_ADMIN) & 0xFFFFFFFF
    data[0].effective   &= mask
    data[0].permitted   &= mask
    data[0].inheritable &= mask
    if libc.capset(ctypes.byref(hdr), data) != 0:
        e = ctypes.get_errno()
        raise OSError(e, f"capset: {os.strerror(e)}")


def _ioctl_work(
    device: str, cmd: int, data_in: bytes,
    *, drop_cap_net_admin: bool = False,
) -> dict:
    import fcntl
    try:
        fd = os.open(device, os.O_RDWR)
    except OSError as e:
        return {"rc": -1, "errno": e.errno, "error": f"open: {e.strerror}"}
    try:
        if drop_cap_net_admin:
            try:
                _drop_cap_net_admin()
            except OSError as e:
                return {"rc": -1, "errno": e.errno,
                        "error": f"capset: {e.strerror}"}
        buf = bytearray(data_in) if data_in else bytearray(0)
        try:
            rc = fcntl.ioctl(fd, cmd, buf, True) if data_in else fcntl.ioctl(fd, cmd, 0)
            return {"rc": int(rc), "errno": 0, "data_hex": bytes(buf).hex()}
        except OSError as e:
            return {"rc": -1, "errno": e.errno, "error": e.strerror}
    finally:
        os.close(fd)


async def ioctl_send(request: web.Request) -> web.Response:
    """POST {device, cmd, data_hex, [uid], [userns], [drop_cap_net_admin],
    [timeout_ms]} -> ioctl result.

    `uid` drops to an unprivileged UID before open (G1-style). `userns`
    runs the call inside an unmapped CLONE_NEWUSER namespace (the
    unmapped-userns capability-gate case). `drop_cap_net_admin` does capset() between
    open and ioctl so a privileged-opened fd hits the dispatcher with
    a stripped effective set (the mid-flight cap-drop case).
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
    userns = bool(body.get("userns", False))
    drop_cap_net_admin = bool(body.get("drop_cap_net_admin", False))
    timeout_s = float(body.get("timeout_ms", 1000)) / 1000.0

    def _work():
        return _ioctl_work(device, cmd, data,
                           drop_cap_net_admin=drop_cap_net_admin)

    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        None,
        lambda: _run_isolated(_work, uid, timeout_s, userns=userns),
    )
    return web.json_response(result)


_EXEC_ARGV0_ALLOWED = {
    "ip", "ethtool", "iptables", "modprobe", "rmmod", "insmod",
    "sysctl", "conntrack", "bridge", "tcpdump",
    # Fuzz harness for cmm's RTNL parser; built from cmm/test/ via
    # `make -C cmm fuzzer`, packaged into the test image alongside cmm.
    "cmm_rtnl_fuzzer",
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
        # bytes + errors='replace' decode — same rationale as cmm_query:
        # any allowlisted command can emit non-UTF-8 bytes (tcpdump -X
        # output, iptables names with high-byte chars, etc.) and the
        # default text=True path raises UnicodeDecodeError → 500.
        r = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: subprocess.run(
                argv, capture_output=True,
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
        "stdout": r.stdout.decode("utf-8", errors="replace"),
        "stderr": r.stderr.decode("utf-8", errors="replace"),
    })


async def fs_read(request: web.Request) -> web.Response:
    """POST {path, [max_bytes]} -> {content_hex, size, errno}.

    Returns file contents hex-encoded so binary payloads (e.g.
    /proc/cdx/last_freed_key under CDX_DEBUG_KEY_ZEROING — see the H2
    regression test) survive transport without UnicodeDecodeError.
    Mirrors fs_write's bytes-discipline. max_bytes caps the response.
    """
    body = await _maybe_json(request)
    try:
        path = body["path"]
    except (KeyError, TypeError) as e:
        return web.json_response({"error": f"bad request: {e}"}, status=400)
    max_bytes = int(body.get("max_bytes", 1 << 20))

    def _work():
        try:
            with open(path, "rb") as f:
                data = f.read(max_bytes)
            return {"content_hex": data.hex(), "size": len(data), "errno": 0}
        except OSError as e:
            return {"content_hex": "", "size": 0,
                    "errno": e.errno, "error": e.strerror}

    result = await asyncio.get_event_loop().run_in_executor(None, _work)
    return web.json_response(result)


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


# Multicast subscription via setsockopt() — kernel uapi value, not in
# the Python `socket` module on every distro we run against.
_SOL_NETLINK            = 270
_NETLINK_ADD_MEMBERSHIP = 1


class _NetlinkListener:
    """Per-id state for /netlink-listen-{start,stop}.

    A blocking AF_NETLINK socket is read by a daemon thread that appends
    each received frame to `frames` under `lock`. Stop closes the socket
    (which unblocks recv with EBADF/0) and joins the thread.
    """

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.frames: list[bytes] = []
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        while not self.stop.is_set():
            try:
                # 64K is the max netlink datagram size; truncation
                # would lose part of a notification we'd then fail to
                # parse. Use MSG_TRUNC if you need to know it happened.
                buf = self.sock.recv(65536)
            except OSError:
                # Socket closed by stop() — exit cleanly.
                return
            if not buf:
                return
            with self.lock:
                self.frames.append(buf)

    def drain(self) -> list[bytes]:
        with self.lock:
            out, self.frames = self.frames, []
        return out

    def shutdown(self) -> None:
        self.stop.set()
        try:
            self.sock.close()
        except OSError:
            pass
        self.thread.join(timeout=2.0)


async def netlink_listen_start(request: web.Request) -> web.Response:
    """POST {protocol, group} -> {listener_id}.

    Opens an AF_NETLINK socket on `protocol`, joins multicast `group`,
    and spawns a daemon thread that buffers received frames. Pair with
    /netlink-listen-stop/{listener_id} to drain + close. The thread-
    based capture mirrors the tcpdump capture pattern: socket I/O off
    the asyncio loop so the event-loop thread stays responsive.
    """
    body = await _maybe_json(request)
    try:
        protocol = int(body["protocol"])
        group    = int(body["group"])
    except (KeyError, ValueError, TypeError) as e:
        return web.json_response({"error": f"bad request: {e}"}, status=400)
    # Group 0 is meaningless for netlink multicast (groups are 1-indexed).
    # The upper bound is just a sanity guard against negative ints
    # silently wrapping into a huge unsigned setsockopt value; the
    # kernel rejects unknown groups with -ENOENT against the protocol's
    # configured ngroups, so we don't need a tight ceiling here.
    if group < 1 or group > 0x7fffffff:
        return web.json_response(
            {"error": f"group must be a positive 32-bit int, got {group}"},
            status=400,
        )
    try:
        sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, protocol)
        # bind(0, 0) — kernel allocates pid; nl_groups bitmask 0 means
        # we don't ask for any groups via the legacy bind path. The
        # NETLINK_ADD_MEMBERSHIP setsockopt below is the modern way
        # (works for group ids beyond the 32-bit nl_groups bitmask).
        sock.bind((0, 0))
        sock.setsockopt(_SOL_NETLINK, _NETLINK_ADD_MEMBERSHIP, group)
    except OSError as e:
        return web.json_response(
            {"error": f"netlink socket setup failed: errno={e.errno} {e.strerror}"},
            status=500,
        )
    listener = _NetlinkListener(sock)
    listener.thread.start()
    listener_id = secrets.token_hex(8)
    request.app["netlink_listeners"][listener_id] = listener
    return web.json_response({"listener_id": listener_id})


async def netlink_listen_stop(request: web.Request) -> web.Response:
    """POST /netlink-listen-stop/{listener_id} -> {messages: [hex,...], count}.

    Drains the buffered frames, closes the socket, joins the reader
    thread. Frames are returned as hex strings so the JSON transport
    is text-clean.
    """
    listener_id = request.match_info["listener_id"]
    listener = request.app["netlink_listeners"].pop(listener_id, None)
    if listener is None:
        return web.json_response({"error": "unknown listener_id"}, status=404)
    # shutdown() blocks on socket.close() + thread.join(); offload so
    # the asyncio loop isn't stalled if the reader is mid-recv.
    await asyncio.get_event_loop().run_in_executor(None, listener.shutdown)
    frames = listener.drain()
    return web.json_response({
        "messages": [f.hex() for f in frames],
        "count":    len(frames),
    })


async def netlink_send(request: web.Request) -> web.Response:
    """POST {protocol, body_hex, [nlmsg_type, nlmsg_flags,
                                  nlmsg_len_override, timeout_ms,
                                  uid, userns]}
    -> raw kernel reply.

    Lower-level than /fci/send: the agent prepends a netlink header but
    everything else is the caller's bytes verbatim. Use this to target
    netlink protocols that aren't FCI (e.g. NETLINK_L2FLOW=33 for
    auto_bridge) or to probe layers that wrap FCI with their own
    structure (like libfci's nlmsg_len trickery from the C2 write-up).

    `uid` / `userns` fork a child that drops privilege before opening
    the netlink socket (the in-kernel netlink_capable gate checks the
    socket opener's credentials), for capability-gate tests.
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
    uid = body.get("uid")
    if uid is not None:
        uid = int(uid)
    userns = bool(body.get("userns", False))
    try:
        if uid is not None or userns:
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: _run_isolated(
                    lambda: _netlink_send_sync(
                        protocol, msg, nlmsg_len_override,
                        nlmsg_type, nlmsg_flags, timeout_s,
                    ),
                    uid, timeout_s, userns=userns,
                ),
            )
        else:
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


# Frames that never own an allocation: the kmemleak/slab machinery and
# the skb construction helpers sitting between the slab and the caller.
_NONOWNER_FRAME = re.compile(
    r"^(kmemleak_|kmem_cache_|__kmalloc|kmalloc|krealloc|slab_"
    r"|__build_skb|build_skb|__alloc_skb|__napi_build_skb)"
)


def _owner_frames(block: str, n: int = 2) -> list[str]:
    """First `n` plausible owner frames of a leak block's backtrace."""
    frames: list[str] = []
    in_bt = False
    for line in block.splitlines():
        if "backtrace" in line:
            in_bt = True
            continue
        if not in_bt:
            continue
        frame = line.strip()
        if not frame:
            continue
        if _NONOWNER_FRAME.match(frame):
            continue
        frames.append(frame)
        if len(frames) >= n:
            break
    return frames


def _kmemleak_filter(blocks: list[str], needles: list[str]) -> list[str]:
    """Keep leak blocks whose ALLOCATION OWNER matches any of `needles`.

    Substring-anywhere matching is unsound: the arm64 frame-pointer
    unwinder occasionally emits a stale frame from a previous stack
    user (observed: every DPAA bpool-seed record from cdx module init
    carrying a bogus `abm_build_l2flow` frame below the cdx frames —
    an impossible call chain that made 4600 X3-class false positives
    match an `abm_` needle). The allocation's owner is within the
    first couple of real frames above the allocator, so only those are
    matched.
    """
    if not needles:
        return blocks
    return [
        b for b in blocks
        if any(n in f for n in needles for f in _owner_frames(b))
    ]


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
    # TWO scans, not one: kmemleak only classifies a white object as
    # reportable once its content checksum is STABLE across consecutive
    # scans (mm/kmemleak.c update_checksum — the first scan just
    # records the CRC and returns false). On a freshly booted DUT the
    # background scanner (10-min cadence) has never run, so a single
    # scan leaves every boot-time allocation unclassified, `clear`
    # misses it, and it surfaces as a "new" leak inside the very next
    # test window.
    def _scan_then_clear() -> None:
        KMEMLEAK_PATH.write_text("scan\n")
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


def build_app() -> web.Application:
    app = web.Application()
    app["captures"] = {}
    app["netlink_listeners"] = {}
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
    app.router.add_post("/netlink-listen-start", netlink_listen_start)
    app.router.add_post("/netlink-listen-stop/{listener_id}", netlink_listen_stop)
    app.router.add_post("/ioctl/send",       ioctl_send)
    app.router.add_post("/fs/read",          fs_read)
    app.router.add_post("/fs/write",         fs_write)
    app.router.add_post("/exec",             exec_cmd)
    return app


def main() -> None:
    host = os.environ.get("ASKD_HOST", "0.0.0.0")
    port = int(os.environ.get("ASKD_PORT", "9110"))
    web.run_app(build_app(), host=host, port=port, access_log=None)


if __name__ == "__main__":
    main()
