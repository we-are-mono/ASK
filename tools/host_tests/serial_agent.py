"""Exercise the actual UART protocol and agent without touching the bench."""

import base64
import concurrent.futures
from contextlib import contextmanager
import os
from pathlib import Path
import queue
import select
import socket
import subprocess
import sys
import termios
import time
from types import SimpleNamespace

import pytest

from askd_agent.wire import Channel, VERSION, parse
from ask_orch.serial import SerialSession


def test_corruption_and_lost_final_ack_do_not_repeat_an_operation():
    left, right = socket.socketpair()
    for sock in (left, right):
        sock.settimeout(0.05)

    def read(sock):
        try:
            data = sock.recv(4096)
        except TimeoutError:
            return b""
        if not data:
            raise EOFError
        return data

    damaged = lost = False
    last = None

    def send(data):
        nonlocal damaged, last
        fields = parse(data)
        last = int(fields[3]) - 1
        if int(fields[2]) == 1 and not damaged:
            damaged = True
            data = data[:-5] + b"0000\n"
        left.sendall(data)

    def acknowledge(data):
        nonlocal lost
        if b" a " in data and int(parse(data)[2]) == last and not lost:
            lost = True
            return
        right.sendall(data)

    sender = Channel(lambda: read(left), send, ack_timeout=0.1)
    receiver = Channel(lambda: read(right), acknowledge, ack_timeout=0.1)
    try:
        value = {"operation": "increment", "payload": base64.b64encode(os.urandom(4096)).decode()}
        sender.send(1, value)
        assert receiver.receive(timeout=1) == (1, value)
        with pytest.raises(queue.Empty):
            receiver.receive(timeout=0.15)
        assert damaged and lost
    finally:
        sender.close()
        receiver.close()
        left.close()
        right.close()


@contextmanager
def uart_process():
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])}
    process = subprocess.Popen([sys.executable, "-m", "askd_agent", "--stdio"],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=env)

    class Pipe:
        timeout = 0.2
        in_waiting = 4096

        def read(self, count):
            if not select.select([process.stdout], [], [], self.timeout)[0]:
                return b""
            data = os.read(process.stdout.fileno(), count)
            if not data:
                raise EOFError(process.stderr.read().decode())
            return data

    def send(data):
        process.stdin.write(data)
        process.stdin.flush()

    try:
        yield process, SimpleNamespace(ser=Pipe(), send=send, log_fp=None)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()


@pytest.fixture
def uart_agent():
    with uart_process() as (process, console):
        session = SerialSession(console, launch=False)
        try:
            yield session
        finally:
            session.close()
            assert process.wait(timeout=5) == 0, process.stderr.read().decode()


def test_eof_cancels_an_operation_and_stops_its_descendants(tmp_path):
    pids = tmp_path / "pids"
    source = ("import os,pathlib,subprocess,sys,time\n"
              "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])\n"
              f"pathlib.Path({str(pids)!r}).write_text(str(os.getpid())+' '+str(child.pid))\n"
              "time.sleep(60)\n")
    with concurrent.futures.ThreadPoolExecutor() as pool:
        with uart_process() as (process, console):
            session = SerialSession(console, launch=False)
            try:
                operation = pool.submit(session.python, source, 10)
                deadline = time.monotonic() + 3
                while not pids.exists():
                    assert time.monotonic() < deadline, "operation never started"
                    time.sleep(0.01)
                process.stdin.close()
                with pytest.raises(ConnectionError):
                    operation.result(timeout=5)
                process.wait(timeout=5)
                for pid in pids.read_text().split():
                    stat = Path(f"/proc/{pid}/stat")
                    assert not stat.exists() or stat.read_text().split()[2] == "Z"
            finally:
                session.stopped.set()
                session.channel.close()
                session.reader.join(timeout=1)


def test_late_response_is_discarded_without_replaying_the_operation(uart_agent, monkeypatch, tmp_path):
    import ask_orch.serial as module

    class ShortWait(queue.Queue):
        def get(self, block=True, timeout=None):
            return super().get(block, min(timeout, 0.05))

    counter = tmp_path / "executions"
    source = ("import pathlib,time\n"
              f"with pathlib.Path({str(counter)!r}).open('a') as out: out.write('once\\n')\n"
              "time.sleep(0.3)\nprint('late result')\n")
    with monkeypatch.context() as patch:
        patch.setattr(module, "queue", SimpleNamespace(Queue=ShortWait, Empty=queue.Empty))
        with pytest.raises(TimeoutError, match="outcome unknown"):
            uart_agent.python(source)
    time.sleep(0.4)
    assert uart_agent.python("print('new result')")["stdout"] == "new result\n"
    assert counter.read_text() == "once\n"
    assert not uart_agent.pending


def test_a_fresh_uart_session_stages_its_own_script_cache():
    source = "print('cached')"
    for _ in range(2):
        with uart_process() as (process, console):
            session = SerialSession(console, launch=False)
            sent = []
            send = session.channel.send

            def record(ident, request):
                sent.append(request)
                send(ident, request)

            session.channel.send = record
            try:
                assert session.python(source)["stdout"] == "cached\n"
                assert session.python(source)["stdout"] == "cached\n"
                assert "source" in sent[0]["body"] and "source" not in sent[1]["body"]
            finally:
                session.close()
                assert process.wait(timeout=5) == 0, process.stderr.read().decode()


def test_stdio_agent_restores_terminal_settings():
    master, slave = os.openpty()
    saved = termios.tcgetattr(slave)
    process = subprocess.Popen([sys.executable, "-m", "askd_agent", "--stdio"],
        stdin=slave, stdout=slave, stderr=subprocess.PIPE,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])})

    def read():
        return os.read(master, 4096) if select.select([master], [], [], 0.1)[0] else b""

    channel = None
    try:
        banner = b""
        deadline = time.monotonic() + 3
        while b"@ASK-READY" not in banner:
            assert time.monotonic() < deadline
            banner += read()
        assert termios.tcgetattr(slave) != saved
        channel = Channel(read, lambda data: os.write(master, data))
        channel.send(1, {"operation": "exit"})
        ident, response = channel.receive(timeout=3)
        assert ident == 1 and response["status"] == 200
        assert process.wait(timeout=3) == 0, process.stderr.read().decode()
        assert termios.tcgetattr(slave) == saved
    finally:
        if channel:
            channel.close()
        if process.poll() is None:
            process.kill()
            process.wait()
        process.stderr.close()
        os.close(master)
        os.close(slave)


def test_prompts_in_any_directory_are_recognised():
    from ask_orch.uart import PROMPT_RE

    for prompt in (b"root@ask-ls1046a:~# ", b"root@ask-ls1046a:/# ",
                   b"root@ask-ls1046a:/tmp/ask-x# ", b"user@host:~/src$ "):
        assert PROMPT_RE.search(b"output\r\n" + prompt), prompt


def test_login_answers_an_unexpected_password_prompt():
    from ask_orch.uart import Console

    master, slave = os.openpty()
    replies = iter([b"\r\nask login: ", b"root\r\nPassword: ", b"\r\nroot@ask:~# "])
    done = []

    def dut():
        # A getty that respawned under the typed name hands the next line to
        # a password prompt; an account without a password accepts an empty
        # one there.
        while not done:
            if select.select([master], [], [], 0.05)[0] and os.read(master, 4096):
                os.write(master, next(replies, b""))

    worker = concurrent.futures.ThreadPoolExecutor(1).submit(dut)
    console = Console(port=os.ttyname(slave))
    try:
        console.login("root", None, timeout=5.0)
    finally:
        done.append(True)
        worker.result(timeout=2)
        console.close()
        os.close(master)
        os.close(slave)


def test_long_operation_keeps_uart_available_and_scripts_are_checked(uart_agent):
    with concurrent.futures.ThreadPoolExecutor() as pool:
        slow = pool.submit(uart_agent.python, "import time; time.sleep(0.8); print('finished')")
        time.sleep(0.1)
        health = uart_agent.request("health")
        assert health["ok"] and health["serial_protocol"] == VERSION
        assert not slow.done()
        assert slow.result()["stdout"] == "finished\n"
    with pytest.raises(RuntimeError, match="digest"):
        uart_agent.request("python", {"sha256": "0" * 64, "source": "raise AssertionError('executed')"})
    source = "print('cached')"
    assert uart_agent.python(source)["stdout"] == uart_agent.python(source)["stdout"] == "cached\n"


def test_uart_preserves_command_errors_and_binary_reads(uart_agent, tmp_path):
    path = tmp_path / "binary"
    path.write_bytes(bytes(range(256)))
    result = uart_agent.request("fs/read", {"path": str(path)})
    assert result["errno"] == 0 and bytes.fromhex(result["content_hex"]) == path.read_bytes()
    result = uart_agent.run("printf evidence; exit 7")
    assert (result.rc, result.stdout) == (7, "evidence")
    with pytest.raises(RuntimeError, match="not allowed"):
        uart_agent.request("exec", {"argv": ["not-an-allowed-command"]})


async def test_binary_writes_arrive_byte_for_byte(uart_agent, tmp_path):
    from ask_orch.client import Agent

    payload = bytes(range(256))
    sent = []

    async def request(session, operation, body, timeout=None):
        sent.append(body)
        return uart_agent.request(operation, body)

    agent = Agent("target")
    agent.request = request
    path = tmp_path / "module.ko"
    result = await agent.fs_write(None, str(path), payload)
    assert result["errno"] == 0 and result["rc"] == len(payload), result
    assert path.read_bytes() == payload
    assert "content" not in sent[0], "bytes must not travel as text"
    text = tmp_path / "sysctl"
    result = await agent.fs_write(None, str(text), "1\n")
    assert result["errno"] == 0 and text.read_text() == "1\n", result


def test_tcp_probe_is_explicit_and_closes(uart_agent):
    probe = uart_agent.request("probe/start", {"address": "127.0.0.1"})
    with socket.create_connection(("127.0.0.1", probe["port"]), timeout=1) as connected:
        assert connected.recv(1) == b""
    uart_agent.request("probe/stop", probe)
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", probe["port"]), timeout=1)


async def test_wan_http_uses_the_same_operations(tmp_path):
    from aiohttp import ClientSession
    from aiohttp.test_utils import TestServer
    from askd_agent.agent import build_app
    from ask_orch.client import Agent

    path = tmp_path / "wan-binary"
    path.write_bytes(bytes(range(256)))
    async with TestServer(build_app()) as server, ClientSession() as http:
        wan = Agent("wan", str(server.make_url("/")).rstrip("/"))
        assert (await wan.health(http))["ok"]
        result = await wan.fs_read(http, str(path))
        assert bytes.fromhex(result["content_hex"]) == path.read_bytes()


async def test_failed_kmemleak_scan_is_an_error_not_a_clean_report(monkeypatch, tmp_path):
    from aiohttp import ClientResponseError, ClientSession
    from aiohttp.test_utils import TestServer
    from askd_agent import agent
    from askd_agent.agent import build_app
    from ask_orch.client import Agent

    monkeypatch.setattr(agent, "KMEMLEAK_PATH", tmp_path / "absent")
    async with TestServer(build_app()) as server, ClientSession() as http:
        target = Agent("target", str(server.make_url("/")).rstrip("/"))
        with pytest.raises(ClientResponseError):
            await target.kmemleak(http, filter_substrs=["[cdx]"])


async def test_slow_kernel_scan_keeps_the_agent_responsive(monkeypatch):
    import asyncio
    import threading
    from askd_agent import agent

    entered, release, finished = (threading.Event() for _ in range(3))

    class KernelScan:
        def exists(self):
            return True

        def write_text(self, value):
            entered.set()
            release.wait(1)
            finished.set()

        def read_text(self):
            return ""

    monkeypatch.setattr(agent, "KMEMLEAK_PATH", KernelScan())
    scan = asyncio.create_task(agent.kmemleak_scan({}, {}))
    try:
        assert await asyncio.to_thread(entered.wait, 1)
        assert (await agent.health({}, {}))["ok"]
        assert not finished.is_set()
    finally:
        release.set()
        result = await scan
    assert result["leak_count"] == 0


async def test_quiet_cleanup_keeps_status_and_stderr(monkeypatch):
    from askd_agent import agent
    monkeypatch.setattr(agent, "_EXEC_ARGV0_ALLOWED", {sys.executable})
    result = await agent.exec_cmd({"argv": [sys.executable, "-c",
        "import sys; print('row' * 100000); print('deleted 4', file=sys.stderr); sys.exit(7)"],
        "quiet": True}, {})
    assert (result["rc"], result["stdout"], result["stderr"]) == (7, "", "deleted 4\n")
