"""CMM's public SysV IPC must preserve unsupported-command replies."""

import shlex
import textwrap

from ask_orch.uart import Console


async def test_cmm_unsupported_commands(splat_window):
    # Match libcmm.c's queue keys, client reservation and packed wire layout.
    script = textwrap.dedent('''
        import ctypes as c
        import errno, os, secrets, struct, time
        lib = c.CDLL(None, use_errno=True)
        lib.ftok.argtypes = [c.c_char_p, c.c_int]
        lib.msgget.argtypes = [c.c_int, c.c_int]
        lib.msgsnd.argtypes = [c.c_int, c.c_void_p, c.c_size_t, c.c_int]
        lib.msgrcv.argtypes = [c.c_int, c.c_void_p, c.c_size_t, c.c_long, c.c_int]
        lib.msgrcv.restype = c.c_ssize_t
        assert c.sizeof(c.c_long) == 8
        pid = int(open('/var/run/cmm.pid').read())
        project = ((pid & 255) ^ ((pid >> 8) & 255)) | 1
        rx = lib.msgget(lib.ftok(b'/tmp', project), 0)
        tx = lib.msgget(lib.ftok(b'/tmp', project ^ 255), 0)
        assert rx >= 0 and tx >= 0, c.get_errno()
        for _ in range(10):
            client = secrets.randbelow(0x7ffffffe) + 1
            path = '/tmp/cmm.' + str(client)
            try:
                fd = os.open(path, os.O_CREAT | os.O_EXCL, 0o600)
                break
            except FileExistsError:
                continue
        else:
            raise AssertionError('cannot reserve CMM client ID')
        codes = (
            0x0202, 0x0203, 0x0204, 0x0205, 0x0206, 0x0207, 0x020f,
            0x0212, 0x0213, 0x0214, 0x0220, 0x0222, 0x0223,
            0x0333, 0x0334, 0x0433, 0x0810, 0x0811, 0x0812,
            0x0c01, 0x0c02, 0x0c03, 0x0d02, 0x0d03, 0x0d04,
            0x0d05, 0x0e02, 0x1001, 0x1002,
        )
        try:
            for code in codes:
                for length in (0, 1, 64, 512):
                    request = c.create_string_buffer(
                        struct.pack('<qHH', client, code, length) + b'Z' * length)
                    assert lib.msgsnd(tx, request, 4 + length, 2048) == 0, c.get_errno()
                    response = c.create_string_buffer(528)
                    deadline = time.monotonic() + 3
                    while True:
                        size = lib.msgrcv(rx, response, 520, client, 2048)
                        if size >= 0:
                            break
                        assert c.get_errno() == errno.ENOMSG, c.get_errno()
                        assert time.monotonic() < deadline, (hex(code), length, 'timeout')
                        time.sleep(0.01)
                    fields = struct.unpack_from('<qiHHH', response.raw)
                    assert size == 10 and fields == (client, 0, code, 2, 1), (
                        hex(code), length, size, fields)
        finally:
            os.close(fd)
            os.unlink(path)
    ''')
    with Console.target() as con:
        con.login("root", None)
        result = con.run("python3 -c " + shlex.quote(script), timeout=40)
        assert result.rc == 0, result.stdout
