"""Compile a ppp unit telling the drivers that offload flows through it that
its channel came or went: the connect, the disconnect, the item that tells of
a disconnect, and the RTM_NEWLINK rtnetlink sends for both."""

import os
import re
from pathlib import Path

from ask_orch.process import run_process
from _host_flowtable import (function)
from _kernel_source import (kernel_source)


def _declaration(source, start):
    return re.search(r"^" + re.escape(start) + r".*?^\};\n", source, re.M | re.S).group()


def _definition(source, name):
    """A definition whose return type sits on the line above its name, as
    ppp_generic.c writes most of its own."""
    match = re.search(r"^static int\n" + name + r"\([^;]*?\)\s*\{", source, re.M)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


def test_a_unit_tells_when_its_channel_comes_or_goes(tmp_path):
    """pppd dialling on demand keeps the unit, its addresses and routes when
    a session ends; only the channel leaves, and a driver that offloaded flows
    through the unit would go on inserting the ended session, so that no
    packet reached the unit to have it dial again. The unit raises
    NETDEV_CHANGEINFODATA when a channel joins -- at once, under RTNL, after
    all_ppp_mutex -- and when one leaves, from its own queue: after the grace
    period that lets every walk which saw the channel add its flow, never
    under the socket, tty or RTNL locks a disconnect runs under, once for the
    disconnects pending together, holding the device until it has run, and
    not at all for a unit that is closing or no longer registered. Userspace
    gets the RTM_NEWLINK a connect always sent, naming no bonding event."""
    kernel = kernel_source()
    generic = (kernel / "drivers/net/ppp/ppp_generic.c").read_text()
    channel = (kernel / "include/linux/ppp_channel.h").read_text()
    rtnetlink = (kernel / "net/core/rtnetlink.c").read_text()

    (tmp_path / "ppp_link_types.inc").write_text(
        _declaration(channel, "struct ppp_channel {")
        + "".join(_declaration(generic, start) for start in (
            "struct ppp_file {", "struct ppp {", "struct channel {", "struct ppp_net {"))
        + re.search(r"^#define ppp_xmit_lock\(ppp\).*?ppp_xmit_unlock\(ppp\); \} while \(0\)\n",
                    generic, re.M | re.S).group())
    (tmp_path / "ppp_link_production.inc").write_text(
        re.search(r"^static struct workqueue_struct \*ppp_link_wq;\n", generic, re.M).group()
        + function(generic, "ppp_link_changed")
        + function(generic, "ppp_link_work")
        + _definition(generic, "ppp_connect_channel")
        + _definition(generic, "ppp_disconnect_channel")
        + function(rtnetlink, "rtnl_get_event")
        + function(rtnetlink, "rtnetlink_event"))
    binary = tmp_path / "flowtable_ppp_link"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra",
        "-Werror", "-Wno-unused-parameter", "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("flowtable_ppp_link.c")), "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })

    # Where the compiled pieces sit. Every unit gets its item before it is
    # registered, and the module's queue outlives every unit.
    configure = function(generic, "ppp_dev_configure")
    assert configure.index("INIT_WORK(&ppp->link_work, ppp_link_work);") < \
        configure.index("ppp_unit_register(")
    init = function(generic, "ppp_init")
    assert init.index("ppp_link_wq = alloc_workqueue(") < init.index("register_pernet_device(")
    assert re.search(r"^out:\n(?:#.*\n)?\tdestroy_workqueue\(ppp_link_wq\);", init, re.M)
    cleanup = function(generic, "ppp_cleanup")
    assert cleanup.index("unregister_pernet_device(") < cleanup.index("destroy_workqueue(ppp_link_wq)")
    # The item is never cancelled or flushed: it takes the RTNL, and the
    # holders of the RTNL that could wait for it are the ones it serves.
    assert not re.search(r"(?:cancel|flush)_work\w*\(&\w+->link_work", generic)
    # The notifier is the one way the unit tells, and replaces the
    # RTM_NEWLINK patch 070 used to send by hand.
    assert generic.count("call_netdevice_notifiers(") == 1
    assert "rtmsg_ifinfo(" not in generic
    # The walk's two hooks report a missing or ended session as a path not
    # known yet; the walk itself is compiled by flowtable_ipsec_route.py.
    walk = function(generic, "ppp_fill_forward_path")
    assert walk.count("return -EAGAIN;") == 2 and "-ENODEV" not in walk
    assert walk.count("return -EOPNOTSUPP;") == 2
