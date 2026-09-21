"""Real fork/exec, pipe and lease fault cases; no DUT or kernel mutation."""
import ctypes
import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import time

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def runner(tmp_path_factory):
    root = tmp_path_factory.mktemp("nft-process")
    (root / "main.c").write_text(r'''
#include "runtime.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    struct ft_ctx ctx = {0};
    signal(SIGPIPE, SIG_IGN);
    int lock = ft_lock(&ctx, 100);
    if (lock < 0) { fprintf(stderr, "%s\n", ctx.err); return 2; }
    char input[128 * 1024 + 1], out[256 * 1024];
    memset(input, 'x', sizeof(input) - 1); input[sizeof(input) - 1] = 0;
    char *cmd[] = {"nft", argv[1], NULL};
    int rc = ft_nft_exec(cmd, input, out, sizeof(out), lock);
    printf("rc=%d len=%zu\n", rc, strlen(out));
    if (rc) fprintf(stderr, "%.240s\n", out);
    if (argc > 2) {
        rc = ft_nft_exec(cmd, input, out, sizeof(out), lock);
        fprintf(stderr, "second rc=%d %.240s\n", rc, out);
    }
    close(lock);
    return rc ? 1 : 0;
}
''')
    # The executable replaces only filesystem paths. All process handling is
    # production code, built with the same sanitizers as controller recovery.
    src = ROOT / "flowtable/src"
    (root / "runtime.h").write_text((src / "runtime.h").read_text().replace(
        '"/run/lock/ask-flowtable.lock"', '"' + str(root / "lock") + '"'))
    for name in ("nft.c", "nft_process.c", "marker.c", "policy.h"):
        (root / name).write_text((src / name).read_text())
    subprocess.run(["cc", "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
                    "-DFT_NFT_TIMEOUT_MS=500", "-DFT_NFT_CLEANUP_MS=500",
                    *map(str, root.glob("*.c")), "-o", str(root / "run")], check=True)
    (root / "nft").write_text(r'''#!/usr/bin/env python3
import json, os, signal, sys, time
from pathlib import Path
root = Path(os.environ['FT_PROCESS_ROOT'])
mode = sys.argv[1]
child = 0
if mode in ('descendant', 'detached-descendant', 'parent-death'):
    child = os.fork()
    if not child:
        if mode == 'detached-descendant':
            os.setsid()
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        time.sleep(3)
        (root / 'late-commit').touch()
        os._exit(0)
(root / 'pids.tmp').write_text(json.dumps({'worker': os.getpid(), 'guardian': os.getppid(), 'child': child}))
(root / 'pids.tmp').replace(root / 'pids')
if mode == 'early-exit':
    sys.exit(0)
if mode == 'output-before-input':
    sys.stdout.write('o' * (128 * 1024))
    sys.stdout.flush()
if mode == 'blocked-input':
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    time.sleep(3)
    (root / 'late-commit').touch()
assert len(sys.stdin.read()) == 128 * 1024
if mode in ('silent', 'parent-death'):
    time.sleep(3)
    (root / 'late-commit').touch()
elif mode == 'closed-output':
    os.close(1)
    os.close(2)
    time.sleep(3)
elif mode == 'endless-output':
    while True:
        os.write(2, b'x' * 4096)
elif mode == 'oversized-output':
    sys.stdout.write('x' * (300 * 1024))
elif mode == 'partial-error':
    os.write(2, b'partial error without newline')
    sys.exit(7)
''')
    (root / "nft").chmod(0o755)
    return root


def env(runner, tmp_path):
    return {**os.environ, "PATH": str(runner) + ":" + os.environ["PATH"],
            "FT_PROCESS_ROOT": str(tmp_path), "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
            "UBSAN_OPTIONS": "halt_on_error=1"}


def wait_for(predicate, seconds=2):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    pytest.fail("process condition did not become true")


@pytest.mark.parametrize("mode,message", [
    ("blocked-input", "deadline"), ("silent", "deadline"),
    ("closed-output", "deadline"), ("endless-output", "deadline"),
    ("oversized-output", "output incomplete"),
    ("early-exit", "input was not completely delivered"),
    ("partial-error", "partial error without newline"),
    ("output-before-input", None), ("descendant", None), ("detached-descendant", None),
])
def test_nft_process_faults(runner, tmp_path, mode, message):
    started = time.monotonic()
    result = subprocess.run([str(runner / "run"), mode], env=env(runner, tmp_path),
                            capture_output=True, text=True, timeout=2)
    assert time.monotonic() - started < 1.7
    assert "AddressSanitizer" not in result.stderr and "runtime error:" not in result.stderr
    assert (result.returncode != 0) == bool(message), result
    if message:
        assert message in result.stderr, result
    if mode == "output-before-input":
        assert "len=131072" in result.stdout
    pids = json.loads((tmp_path / "pids").read_text())
    assert all(not Path(f"/proc/{pid}").exists() for pid in pids.values() if pid), pids
    assert not (tmp_path / "late-commit").exists()
    with (runner / "lock").open("r+") as lease:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)


@pytest.fixture
def adopt_guardians():
    # Reap known orphan guardians ourselves instead of depending on the test
    # machine's PID 1; restore the pytest process's original subreaper setting.
    libc = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()
    assert libc.prctl(37, ctypes.byref(previous), 0, 0, 0) == 0
    assert libc.prctl(36, 1, 0, 0, 0) == 0
    guardians = []
    try:
        yield guardians
    finally:
        for pid in guardians:
            try:
                os.kill(pid, signal.SIGCONT)
                wait_for(lambda: os.waitpid(pid, os.WNOHANG)[0] == pid)
            except (ChildProcessError, ProcessLookupError):
                pass
        assert libc.prctl(36, previous.value, 0, 0, 0) == 0


def test_controller_death_cancels_entire_job(runner, tmp_path, adopt_guardians):
    process = subprocess.Popen([str(runner / "run"), "parent-death"],
                               env=env(runner, tmp_path), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        wait_for(lambda: (tmp_path / "pids").exists())
        pids = json.loads((tmp_path / "pids").read_text())
        adopt_guardians.append(pids["guardian"])
        started = time.monotonic()
        process.kill()
        process.communicate(timeout=1)  # no guardian retained controller pipes
        wait_for(lambda: all(not Path(f"/proc/{pids[k]}").exists() for k in ("worker", "child")))
        assert time.monotonic() - started < 0.5  # liveness EOF, not the job timeout
        with (runner / "lock").open("r+") as lease:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        time.sleep(0.55)
        assert not (tmp_path / "late-commit").exists()
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=2)


def test_unfinished_cleanup_retains_lease_and_bounds_caller(runner, tmp_path, adopt_guardians):
    process = subprocess.Popen([str(runner / "run"), "blocked-input", "repeat"],
                               env=env(runner, tmp_path), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    guardian = None
    try:
        wait_for(lambda: (tmp_path / "pids").exists())
        pids = json.loads((tmp_path / "pids").read_text())
        guardian = pids["guardian"]
        adopt_guardians.append(guardian)
        os.kill(guardian, signal.SIGSTOP)
        started = time.monotonic()
        _, error = process.communicate(timeout=1.8)
        assert time.monotonic() - started < 1.7
        assert b"deadline" in error and b"previous nft cleanup still holds" in error, error
        with (runner / "lock").open("r+") as lease:
            with pytest.raises(BlockingIOError):
                fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.kill(guardian, signal.SIGCONT)
        wait_for(lambda: not Path(f"/proc/{pids['worker']}").exists())
        assert not (tmp_path / "late-commit").exists()
    finally:
        if guardian:
            os.kill(guardian, signal.SIGCONT)
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=2)
