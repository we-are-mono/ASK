"""Small DUT-side client for the route test's normal CMM socket commands."""
import ctypes as c
import errno
import os
import secrets
import struct
import sys
import time

lib = c.CDLL(None, use_errno=True)
lib.ftok.argtypes = [c.c_char_p, c.c_int]
lib.msgget.argtypes = [c.c_int, c.c_int]
lib.msgsnd.argtypes = [c.c_int, c.c_void_p, c.c_size_t, c.c_int]
lib.msgrcv.argtypes = [c.c_int, c.c_void_p, c.c_size_t, c.c_long, c.c_int]
lib.msgrcv.restype = c.c_ssize_t
pid = int(open('/var/run/cmm.pid').read())
project = ((pid & 255) ^ ((pid >> 8) & 255)) | 1
rx = lib.msgget(lib.ftok(b'/tmp', project), 0)
tx = lib.msgget(lib.ftok(b'/tmp', project ^ 255), 0)
assert rx >= 0 and tx >= 0, c.get_errno()
code, payload = int(sys.argv[1], 0), bytes.fromhex(sys.argv[2])
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
try:
    request = c.create_string_buffer(struct.pack('<qHH', client, code, len(payload)) + payload)
    assert lib.msgsnd(tx, request, 4 + len(payload), 2048) == 0, c.get_errno()
    response = c.create_string_buffer(528)
    deadline = time.monotonic() + 5
    while True:
        size = lib.msgrcv(rx, response, 520, client, 2048)
        if size >= 0:
            break
        assert c.get_errno() == errno.ENOMSG, c.get_errno()
        assert time.monotonic() < deadline, 'CMM response timeout'
        time.sleep(0.01)
    _, daemon_rc, reply_code, length = struct.unpack_from('<qiHH', response.raw)
    assert daemon_rc == 0 and reply_code == code and size == 8 + length, (size, response.raw.hex())
    reply_rc = struct.unpack_from('<H', response.raw, 16)[0]
    assert reply_rc == 0, reply_rc
finally:
    os.close(fd)
    os.unlink(path)
