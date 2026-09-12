"""A running classifier must reject another loader before hardware changes."""

import errno
import shlex

from ask_orch.uart import Console
from _ioctl import CDX_CTRL_DPA_INIT_CHECK


async def test_dpa_init_check(aiohttp_session, target_agent, splat_window):
    result = await target_agent.ioctl_send(
        aiohttp_session, device="/dev/cdx_ctrl", cmd=CDX_CTRL_DPA_INIT_CHECK, data=b"",
    )
    assert result.get("errno") == errno.EBUSY, result


async def test_port_tree_replacement_unsupported(splat_window):
    # Reserved native (8-byte object) and compat (4-byte object) command
    # numbers. Even unreadable arguments must be rejected before decoding.
    script = """
import errno, fcntl, glob, os
devices = sorted(glob.glob('/dev/fm0-port-*'))
assert devices, 'no FMAN port devices'
checked = 0
for device in devices:
    try:
        fd = os.open(device, os.O_RDWR)
    except OSError as error:
        if error.errno == errno.ENODEV:  # Static node for an inactive port.
            continue
        raise
    try:
        for command in (0x4008e162, 0x4004e162):
            for argument in (0, 1):
                try:
                    fcntl.ioctl(fd, command, argument)
                except OSError as error:
                    assert error.errno == errno.EOPNOTSUPP, (device, hex(command), error)
                else:
                    raise AssertionError('whole-tree replacement accepted')
        checked += 1
    finally:
        os.close(fd)
assert checked, 'no active FMAN port devices'
print('whole-tree replacement rejected on %d ports' % checked)
"""
    with Console.target() as con:
        con.login("root", None)
        result = con.run("python3 -c " + shlex.quote(script), timeout=20)
        assert result.rc == 0, result.stdout


async def test_dpa_duplicate_startup(splat_window):
    with Console.target() as con:
        con.login("root", None)
        for _ in range(3):
            result = con.run("/usr/bin/dpa_app", timeout=15)
            assert result.rc != 0, result.stdout
            assert "initialization refused" in result.stdout, result.stdout
            assert "Device or resource busy" in result.stdout, result.stdout


async def test_dpa_exclusive_control_fd(splat_window):
    script = """
import errno, os
fd = os.open('/dev/cdx_ctrl', os.O_RDWR)
try:
    for _ in range(16):
        try:
            second = os.open('/dev/cdx_ctrl', os.O_RDWR)
        except OSError as error:
            assert error.errno == errno.EBUSY, error
        else:
            os.close(second)
            raise AssertionError('second opener admitted during DPA startup ownership')
finally:
    os.close(fd)
os.close(os.open('/dev/cdx_ctrl', os.O_RDWR))
"""
    with Console.target() as con:
        con.login("root", None)
        result = con.run("python3 -c " + shlex.quote(script), timeout=15)
        assert result.rc == 0, result.stdout


async def test_dpa_unused_hash_table_teardown(splat_window):
    # Native arm64 fm_pcd_ioctls.h: 120-byte hash parameters, id at 112.
    # Use a private two-bucket Ethernet table with a drop miss action.
    # It is never attached to a root or used by the running dataplane.
    script = """
import ctypes, errno, fcntl, mmap, os, struct
create, delete = 0xc078e139, 0x4008e139
params = bytearray(120)
struct.pack_into('<H', params, 0, 2)   # max_num_of_keys
struct.pack_into('<H', params, 10, 1)  # hash_res_mask
params[13] = 12                       # match_key_size
struct.pack_into('<I', params, 16, 1)  # next_engine = DONE
struct.pack_into('<I', params, 24, 1)  # enqueue action = DROP
struct.pack_into('<I', params, 68, 9)  # table_type = ETHERNET_TABLE
fd = os.open('/dev/fm0-pcd', os.O_RDWR)
try:
    for _ in range(64):
        data = bytearray(params)
        fcntl.ioctl(fd, create, data)
        cookie = data[112:120]
        assert cookie != bytes(8)
        fcntl.ioctl(fd, delete, cookie)
        try:
            fcntl.ioctl(fd, delete, cookie)
        except OSError:
            pass
        else:
            raise AssertionError('deleted hash cookie accepted twice')
    # Fail copy_to_user after hardware creation. More than 1024 attempts
    # exceed the cookie registry capacity if any attempt leaks its slot.
    libc = ctypes.CDLL(None, use_errno=True)
    page = mmap.mmap(-1, mmap.PAGESIZE)
    page[:len(params)] = params
    address = ctypes.addressof(ctypes.c_char.from_buffer(page))
    assert libc.mprotect(ctypes.c_void_p(address), mmap.PAGESIZE, mmap.PROT_READ) == 0
    try:
        for _ in range(1100):
            assert libc.ioctl(fd, ctypes.c_ulong(create), ctypes.c_void_p(address)) == -1
    finally:
        assert libc.mprotect(ctypes.c_void_p(address), mmap.PAGESIZE,
                             mmap.PROT_READ | mmap.PROT_WRITE) == 0
        page.close()
    data = bytearray(params)
    fcntl.ioctl(fd, create, data)
    fcntl.ioctl(fd, delete, data[112:120])
finally:
    os.close(fd)
"""
    with Console.target() as con:
        con.login("root", None)
        result = con.run("python3 -c " + shlex.quote(script), timeout=45)
        assert result.rc == 0, result.stdout


async def test_hardware_reassembly_unsupported(splat_window):
    # Native arm64 UAPI values/layouts are asserted by sdk_port_ioctl.c.
    # Invalid nested pointers ensure rejection precedes cookie resolution.
    script = """
import errno, fcntl, glob, os, struct

def rejected(fd, command, data):
    before = bytes(data)
    try:
        fcntl.ioctl(fd, command, data)
    except OSError as error:
        assert error.errno == errno.EOPNOTSUPP, (hex(command), error)
    else:
        raise AssertionError('hardware reassembly accepted')
    assert bytes(data) == before, 'rejected request changed its arguments'

fd = os.open('/dev/fm0-pcd', os.O_RDWR)
try:
    data = bytearray(b'\\xff' * 464)
    struct.pack_into('<I', data, 0, 1)  # MANIP_REASSEM; all headers unsupported.
    rejected(fd, 0xc1d0e13f, data)
    for table_type in (14, 15, 0xfffffffe, 0xffffffff):
        data = bytearray(b'\\xff' * 120)
        struct.pack_into('<I', data, 68, table_type)
        rejected(fd, 0xc078e139, data)
finally:
    os.close(fd)
checked = 0
for device in sorted(glob.glob('/dev/fm0-port-*')):
    try:
        fd = os.open(device, os.O_RDWR)
    except OSError as error:
        if error.errno == errno.ENODEV:
            continue
        raise
    try:
        for ip, capwap in ((1, 0), (0, 1), (1, 1)):
            data = bytearray(b'\\xff' * 64)
            struct.pack_into('<QQ', data, 48, ip, capwap)
            rejected(fd, 0x4040e15a, data)
        checked += 1
    finally:
        os.close(fd)
assert checked, 'no active FMAN ports'
print('reassembly creation and attachment rejected on %d ports' % checked)
"""
    with Console.target() as con:
        con.login("root", None)
        result = con.run("python3 -c " + shlex.quote(script), timeout=20)
        assert result.rc == 0, result.stdout
