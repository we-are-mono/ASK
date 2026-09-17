"""One UART, one reader — enforced, not merely documented.

Serial reads are destructive: whichever reader calls read() first takes the
bytes, and the other never sees them. Two Console objects on one device
therefore deadlock rather than merely interleave, and the rig hit exactly
that — the module lifecycle test opens its own console while the rig fixture
holds one, and both blocked in _pump() for 76 minutes waiting for a sentinel
the other had already consumed.

A per-instance lock cannot fix it, because neither instance can see the other.
These tests pin the property that actually matters: the lock is keyed by
device and shared across instances.
"""

import os
import re
import threading

import pytest

serial = pytest.importorskip("serial", reason="pyserial required for console tests")

from ask_orch.uart import Console, port_lock  # noqa: E402


@pytest.fixture
def pty_port():
    """A pty pair; yields (master_fd, slave_path) and closes both after."""
    master, slave = os.openpty()
    try:
        yield master, os.ttyname(slave)
    finally:
        for fd in (master, slave):
            try:
                os.close(fd)
            except OSError:
                pass


def test_lock_is_shared_per_device_not_per_instance(pty_port):
    """Two consoles on one device share a lock; different devices do not."""
    _, path = pty_port
    a, b = Console(path), Console(path)
    try:
        assert a.lock is b.lock, "per-instance locks would not see each other"
        assert port_lock(path) is a.lock
        assert port_lock("/dev/does-not-exist") is not a.lock
    finally:
        a.close()
        b.close()


def test_two_readers_on_one_port_do_not_eat_each_others_output(pty_port):
    """Concurrent run() calls from two consoles both get their own answer.

    Without serialisation each thread's _pump() consumes whatever arrives,
    including the other's marker, and both run() calls time out. The responder
    below answers one command at a time, which is what a real shell does.
    """
    master, path = pty_port
    a, b = Console(path, timeout_s=5), Console(path, timeout_s=5)
    stop = threading.Event()

    def shell():
        """Echo back a prompt and the marker the console is waiting for."""
        pending = b""
        while not stop.is_set():
            try:
                pending += os.read(master, 4096)
            except OSError:
                return
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                m = re.search(rb"echo (__ASK_RC_[0-9_]+__)=\$\?", line)
                if m:
                    os.write(master, b"output\r\n" + m.group(1) + b"=0\r\n# ")

    responder = threading.Thread(target=shell, daemon=True)
    responder.start()

    results, errors = {}, {}

    def drive(name, console):
        try:
            results[name] = console.run(f"true {name}", timeout=5)
        except Exception as exc:                      # noqa: BLE001
            errors[name] = exc

    threads = [threading.Thread(target=drive, args=(n, c))
               for n, c in (("a", a), ("b", b))]
    try:
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=20)
            assert not t.is_alive(), "run() never returned — the deadlock is back"
        assert not errors, errors
        assert set(results) == {"a", "b"}
        for name, r in results.items():
            assert r.rc == 0, (name, r)
    finally:
        stop.set()
        a.close()
        b.close()
        responder.join(timeout=2)
