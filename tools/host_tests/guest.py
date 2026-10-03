"""QGA carries large scripts without a shell upload or an IP route."""

import base64
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
from types import SimpleNamespace
import zlib

import pytest

from ask_orch.guest import Guest


def test_exec_preserves_source_errors_and_rejects_truncated_results(monkeypatch):
    source = "print('quoted'); # " + "large script " * 20000
    status = {"exited": True, "exitcode": 7,
              "out-data": base64.b64encode(b"evidence\n").decode()}

    def virsh(argv, *, input, **kwargs):
        command = shlex.split(input)
        request = json.loads(command[-1])
        if request["execute"] == "guest-exec":
            args = request["arguments"]
            assert zlib.decompress(base64.b64decode(args["input-data"])).decode() == source
            assert args["path"] == "/usr/bin/timeout"
            response = {"return": {"pid": 42}}
        else:
            assert request["arguments"] == {"pid": 42}
            response = {"return": status}
        return SimpleNamespace(returncode=0, stdout="virsh # " + input + json.dumps(response) + "\nvirsh # \n", stderr="")

    monkeypatch.setattr("ask_orch.guest.subprocess.run", virsh)
    guest = Guest("domain with spaces")
    result = guest.python(source)
    assert (result.rc, result.stdout) == (7, "evidence\n")
    status["out-truncated"] = True
    with pytest.raises(RuntimeError, match="truncated"):
        guest.python(source)


@pytest.mark.parametrize("failure", ["launch", "status", "deadline"])
def test_uncertain_result_is_not_replayed_and_next_command_works(monkeypatch, failure):
    import ask_orch.guest as module

    guest = Guest("local")
    launches = []
    elapsed = iter(range(0, 1000, 20))
    monkeypatch.setattr(module, "time", SimpleNamespace(
        monotonic=lambda: next(elapsed), sleep=lambda _: None))

    def rpc(operation, **arguments):
        if operation == "guest-exec":
            launches.append(arguments)
            if failure == "launch" and len(launches) == 1:
                raise TimeoutError("launch response lost")
            return {"pid": len(launches)}
        assert arguments == {"pid": len(launches)}
        if len(launches) == 1:
            if failure == "status":
                raise TimeoutError("status response lost")
            return {"exited": False}
        return {"exited": True, "exitcode": 0,
                "out-data": base64.b64encode(b"next command\n").decode()}

    monkeypatch.setattr(guest, "rpc", rpc)
    with pytest.raises(TimeoutError):
        guest.run("first operation", timeout=1)
    assert len(launches) == 1
    assert guest.run("unrelated operation", timeout=1).stdout == "next command\n"
    assert [item["arg"][-1] for item in launches] == ["first operation", "unrelated operation"]


def test_guest_deadline_stops_descendants(monkeypatch, tmp_path):
    guest = Guest("local")
    processes = []
    pids = tmp_path / "pids"
    source = ("import os,pathlib,subprocess,sys,time\n"
              "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])\n"
              f"pathlib.Path({str(pids)!r}).write_text(str(os.getpid())+' '+str(child.pid))\n"
              "time.sleep(60)\n")

    def rpc(operation, **arguments):
        if operation == "guest-exec":
            process = subprocess.Popen([arguments["path"], *arguments["arg"]],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True)
            process.stdin.write(base64.b64decode(arguments["input-data"]))
            process.stdin.close()
            process.stdin = None
            processes.append(process)
            return {"pid": process.pid}
        process, = processes
        assert arguments == {"pid": process.pid}
        if process.poll() is None:
            return {"exited": False}
        out, err = process.communicate(timeout=2)
        return {"exited": True, "exitcode": process.returncode,
                "out-data": base64.b64encode(out).decode(),
                "err-data": base64.b64encode(err).decode()}

    monkeypatch.setattr(guest, "rpc", rpc)
    try:
        assert guest.python(source, timeout=0.5).rc == 124
        assert len(processes) == 1
        for pid in pids.read_text().split():
            stat = Path(f"/proc/{pid}/stat")
            assert not stat.exists() or stat.read_text().split()[2] == "Z"
    finally:
        for process in processes:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate(timeout=2)
