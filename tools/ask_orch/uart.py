"""UART/serial-console wrapper for the test harness bootstrap.

Lets the orchestrator drive the DUT and the LAN-side traffic generator
over their serial consoles without any network prerequisite. Used before
the HTTP agent is reachable (fresh boot, no control-plane NIC yet,
post-panic recovery).

Scripted command execution only — for an interactive terminal, use `tio`
directly (`tio /dev/ttyUSB0` or `tio $(sudo virsh ttyconsole <vm>)`).

Endpoints:
    target: USB-serial to the DUT. Path from $ASK_TARGET_DEV
            (default /dev/ttyUSB0).
    lan:    libvirt-hosted LAN-side traffic generator VM. Domain name
            from $ASK_LAN_VM (default "loki"). PTY resolved via
            `virsh ttyconsole <domain>`.

Both require root (or dialout + libvirt groups depending on distro).

CLI usage (as root):
    python -m ask_orch.uart target --run 'uname -a'
    python -m ask_orch.uart lan    --login root:toor --run 'ip a'
"""

from __future__ import annotations

import argparse
import os
import re
import select
import subprocess
import sys
import time
from dataclasses import dataclass

import serial


DEFAULT_TARGET_DEV = os.environ.get("ASK_TARGET_DEV", "/dev/ttyUSB0")
DEFAULT_LAN_VM     = os.environ.get("ASK_LAN_VM", "loki")
DEFAULT_BAUD       = 115200

# Patterns we expect to see from the remote shell. Kept loose — BusyBox,
# systemd's agetty, Armbian, and Yocto all use slightly different prompts.
LOGIN_RE    = re.compile(rb"(\w[\w.-]*)\s+login:\s*$", re.MULTILINE)
PASSWORD_RE = re.compile(rb"[Pp]assword:\s*$")
# Root prompt heuristic. Matches at end-of-buffer: "<hostuser>@... # " or "$ ".
# No leading-newline anchor because the first prompt after login can land at
# the very start of what we've buffered so far.
PROMPT_RE   = re.compile(rb"[-@\w.:~]+[#$]\s*$")

# ANSI CSI / OSC escape sequences (bracketed-paste, colors, cursor moves, etc.)
# Stripped on ingest so PROMPT_RE's `$` anchor isn't broken by invisibles.
_ANSI_CSI_RE = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]")
_ANSI_OSC_RE = re.compile(rb"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")


def _strip_ansi(b: bytes) -> bytes:
    return _ANSI_OSC_RE.sub(b"", _ANSI_CSI_RE.sub(b"", b))


@dataclass
class RunResult:
    cmd:    str
    stdout: str
    rc:     int


class Console:
    """Thin serial wrapper with send/expect + login + run-and-exit-code.

    Keeps a rolling read buffer so overlapping reads don't lose data.
    Logs all raw I/O to `log_path` if set, which is invaluable for
    debugging test failures after the fact.
    """

    def __init__(self, port: str, baud: int = DEFAULT_BAUD,
                 timeout_s: float = 5.0, log_path: str | None = None):
        self.port      = port
        self.timeout_s = timeout_s
        self.buf       = b""
        self.log_fp    = open(log_path, "ab", buffering=0) if log_path else None
        self.ser       = serial.Serial(port=port, baudrate=baud, timeout=0)

    # --- factory helpers ------------------------------------------------

    @classmethod
    def target(cls, **kw) -> "Console":
        return cls(port=DEFAULT_TARGET_DEV, **kw)

    @classmethod
    def lan(cls, domain: str | None = None, **kw) -> "Console":
        """Open the LAN-side VM's serial console by libvirt domain name."""
        pty = _virsh_pty(domain or DEFAULT_LAN_VM)
        return cls(port=pty, **kw)

    # --- primitives -----------------------------------------------------

    def send(self, data: bytes | str) -> None:
        if isinstance(data, str):
            data = data.encode()
        if self.log_fp:
            self.log_fp.write(b"<SEND>" + data + b"</SEND>\n")
        self.ser.write(data)
        self.ser.flush()

    def expect(self, pattern: re.Pattern[bytes] | bytes | str,
               timeout: float | None = None) -> tuple[re.Match[bytes], bytes]:
        """Read until `pattern` matches the tail of the rolling buffer.

        Returns (match, before) where `before` is everything in the buffer
        up to (but not including) the match. The match itself and anything
        after it are kept in `self.buf` — so a follow-on expect() sees the
        post-match bytes, which is what you want for sequenced patterns.
        Raises TimeoutError if not seen in time.
        """
        if isinstance(pattern, (bytes, str)):
            pat = re.compile(pattern if isinstance(pattern, bytes) else pattern.encode())
        else:
            pat = pattern
        deadline = time.monotonic() + (timeout if timeout is not None else self.timeout_s)
        while True:
            self._pump(timeout_s=0.1)
            m = pat.search(self.buf)
            if m:
                before = self.buf[:m.start()]
                self.buf = self.buf[m.end():]
                return m, before
            if time.monotonic() > deadline:
                tail = self.buf[-400:].decode(errors="replace")
                raise TimeoutError(
                    f"expect({pat.pattern!r}) timed out on {self.port}; "
                    f"tail: {tail!r}"
                )

    def _pump(self, timeout_s: float) -> None:
        r, _, _ = select.select([self.ser.fileno()], [], [], timeout_s)
        if not r:
            return
        try:
            chunk = os.read(self.ser.fileno(), 4096)
        except BlockingIOError:
            # select can wake spuriously on some kernels / USB-serial drivers;
            # a non-blocking read then returns EAGAIN. Just try again next pump.
            return
        if not chunk:
            return
        if self.log_fp:
            self.log_fp.write(b"<RECV>" + chunk + b"</RECV>\n")
        # Append raw then strip over the whole buffer — a multi-byte escape
        # sequence can split across read() boundaries (e.g. `\x1b[` in one
        # chunk, `?2004l` in the next). Per-chunk strip would miss those.
        # Partial sequences at the tail survive this pass and get stripped
        # once the next pump completes them.
        self.buf = _strip_ansi(self.buf + chunk)

    # --- login / prompt sync -------------------------------------------

    def sync_prompt(self, tries: int = 3, timeout: float = 1.0) -> None:
        """Ping the console until we see a shell prompt.

        Sends a harmless Enter to jostle the remote into printing its
        prompt. Idempotent — safe to call multiple times.
        """
        for _ in range(tries):
            self.send(b"\n")
            try:
                self.expect(PROMPT_RE, timeout=timeout)
                return
            except TimeoutError:
                continue
        raise TimeoutError(f"no prompt on {self.port} after {tries} tries")

    def login(self, user: str, password: str | None = None,
              timeout: float = 5.0) -> None:
        """Log in if sitting at a login prompt; no-op at an already-logged-in shell."""
        self.send(b"\n")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self._pump(0.3)
            if PROMPT_RE.search(self.buf):
                self.buf = b""
                return
            if LOGIN_RE.search(self.buf):
                self.buf = b""
                self.send(user + "\n")
                if password is not None:
                    self.expect(PASSWORD_RE, timeout=5.0)
                    self.send(password + "\n")
                self.expect(PROMPT_RE, timeout=10.0)
                return
        raise TimeoutError(f"login timed out on {self.port}")

    # --- command execution ---------------------------------------------

    def run(self, cmd: str, timeout: float = 10.0) -> RunResult:
        """Run `cmd` in the remote shell, return stdout + exit code.

        Uses a sentinel marker to disambiguate command output from the
        shell prompt echo — `echo __ASK_RC=$?__` after the command.
        """
        marker = f"__ASK_RC_{os.getpid()}_{int(time.monotonic() * 1e6)}__"
        wrapped = f"{cmd}; echo {marker}=$?\n"
        self.send(wrapped)

        # Everything between "the shell's echo of our wrapped command"
        # and the marker is the real command output.
        marker_re = re.compile(rf"{re.escape(marker)}=(\-?\d+)".encode())
        m, before = self.expect(marker_re, timeout=timeout)
        rc = int(m.group(1))

        # Flush up to the next prompt so the buffer is clean for subsequent
        # commands; we ignore what's in there (just the post-marker prompt).
        try:
            self.expect(PROMPT_RE, timeout=5.0)
        except TimeoutError:
            pass

        raw = before.decode(errors="replace")
        out = _strip_echo(raw, wrapped)
        return RunResult(cmd=cmd, stdout=out, rc=rc)

    # --- ctx manager ---------------------------------------------------

    def close(self) -> None:
        try:
            self.ser.close()
        finally:
            if self.log_fp:
                self.log_fp.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def _virsh_pty(domain: str) -> str:
    """Resolve a libvirt domain's serial PTY path (e.g. /dev/pts/9)."""
    try:
        r = subprocess.run(
            ["virsh", "ttyconsole", domain],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except FileNotFoundError:
        raise RuntimeError("virsh not found — install libvirt-clients")
    if r.returncode != 0:
        # Try with sudo if direct virsh fails (QEMU:///system needs root).
        r = subprocess.run(
            ["sudo", "virsh", "ttyconsole", domain],
            capture_output=True, text=True, timeout=5, check=False,
        )
    if r.returncode != 0:
        raise RuntimeError(f"virsh ttyconsole {domain} failed: {r.stderr.strip()}")
    pty = r.stdout.strip()
    if not pty.startswith("/dev/pts/"):
        raise RuntimeError(f"unexpected virsh ttyconsole output: {pty!r}")
    return pty


def _strip_echo(raw: str, wrapped_cmd: str) -> str:
    """Remove the shell's local echo of the sent command from output."""
    first_line = wrapped_cmd.rstrip("\n").splitlines()[0]
    # The echo appears followed by CR/LF. Find its end and drop everything up to there.
    for newline in ("\r\n", "\n"):
        idx = raw.find(first_line + newline)
        if idx >= 0:
            return raw[idx + len(first_line) + len(newline):]
    return raw


# --------------------------------------------------------------------- CLI

def _main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="ask_orch.uart",
        description="Scripted serial-console access for target/LAN-VM. "
                    "For an interactive terminal, use `tio` directly.",
    )
    p.add_argument("endpoint", choices=("target", "lan"))
    p.add_argument("--run", required=True,
                   help="command to run on the remote shell")
    p.add_argument("--login", help="user[:password] to log in as first")
    p.add_argument("--log", help="write raw I/O to this file")
    p.add_argument("--timeout", type=float, default=5.0)
    args = p.parse_args(argv)

    factory = Console.target if args.endpoint == "target" else Console.lan
    con = factory(log_path=args.log)
    try:
        if args.login:
            user, _, pw = args.login.partition(":")
            con.login(user, pw if pw else None)
        else:
            con.sync_prompt()

        r = con.run(args.run, timeout=args.timeout)
        sys.stdout.write(r.stdout)
        return r.rc
    finally:
        con.close()


if __name__ == "__main__":
    sys.exit(_main())
