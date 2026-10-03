"""LAN VM commands over its existing QEMU guest-agent virtio channel."""

import base64
import json
import shlex
import subprocess
import time
import zlib

from .uart import RunResult


class Guest:
    def __init__(self, domain):
        self.domain = domain

    def rpc(self, operation, **arguments):
        request = json.dumps({"execute": operation, "arguments": arguments})
        # stdin avoids Linux's per-argument size limit on large test scripts.
        # virsh quotes/echoes its input; the QGA reply is the sole JSON line.
        command = shlex.join(["qemu-agent-command", self.domain, "--timeout", "10", request])
        result = subprocess.run(["virsh", "-c", "qemu:///system", "--quiet"],
                                input=command + "\n", capture_output=True, text=True, timeout=15)
        replies = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
        if result.returncode or len(replies) != 1 or "error" in replies[0]:
            raise RuntimeError(f"LAN {operation} failed; outcome unknown: {result.stderr} {replies}")
        return replies[0]["return"]

    def check(self):
        info = self.rpc("guest-info")
        enabled = {c["name"] for c in info["supported_commands"] if c["enabled"]}
        if not {"guest-exec", "guest-exec-status"} <= enabled:
            raise RuntimeError("LAN VM needs qemu-guest-agent with guest-exec enabled")
        result = self.run("command -v python3 && command -v timeout")
        if result.rc:
            raise RuntimeError("LAN VM needs Python 3 and coreutils timeout: " + result.stdout)
        return info["version"]

    def execute(self, argv, *, data=b"", timeout=30):
        started = self.rpc("guest-exec", path="/usr/bin/timeout",
                           arg=["-k", "2", str(timeout), *argv],
                           **{"input-data": base64.b64encode(data).decode(), "capture-output": True})
        deadline = time.monotonic() + timeout + 15
        while True:
            result = self.rpc("guest-exec-status", pid=started["pid"])
            if result["exited"]:
                if result.get("out-truncated") or result.get("err-truncated"):
                    raise RuntimeError("LAN command output was truncated")
                output = b"".join(base64.b64decode(result.get(key, ""))
                                  for key in ("out-data", "err-data")).decode(errors="replace")
                return RunResult(shlex.join(argv), output,
                                 result.get("exitcode", -result.get("signal", 1)))
            if time.monotonic() >= deadline:
                raise TimeoutError("LAN command result missing; operation outcome unknown")
            time.sleep(0.1)

    def run(self, command, timeout=30):
        return self.execute(["/bin/sh", "-c", command], timeout=timeout)

    def python(self, source, timeout=30):
        return self.execute(["python3", "-c",
                             "import sys,zlib; exec(compile(zlib.decompress(sys.stdin.buffer.read()), "
                             "'<ask-lan>', 'exec'))"],
                            data=zlib.compress(source.encode(), 1), timeout=timeout)
