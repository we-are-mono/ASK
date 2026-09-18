"""The multicast membership learner's decision logic."""

import os
from pathlib import Path
import re
import subprocess

from test_qos_lifecycle import function

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "cdx/ask_flowtable.c"


def test_mcast_learner(tmp_path):
    source = SOURCE.read_text()
    # The real group and port descriptions, not restatements: a field added or
    # resized on either has to fail here rather than compile into a harness
    # that no longer matches what the adapter keeps.
    (tmp_path / "mcast_learner.inc").write_text(
        source[source.index("struct ft_mc_port {"):source.index("static LIST_HEAD(ft_mc_groups)")]
        # The observation the hook records, declared further down with the
        # traffic half rather than with the group it resolves against.
        + source[source.index("struct ft_mc_seen {"):
                 source.index("};", source.index("struct ft_mc_seen {")) + 3]
        # The extraction order is the file's, which is not a valid declaration
        # order on its own: ft_mc_membership calls helpers defined after it in
        # the list. Forward-declare rather than reorder, so the harness does
        # not silently depend on where a function sits in the source.
        + "static bool ft_mc_port_eligible(struct net_device *dev);\n"
          "static int ft_mc_port_tags(struct net_device *bridge,\n"
          "                           struct net_device *port, u16 vid,\n"
          "                           struct cdx_ft_vlan *stack, u8 *count);\n"
          "static struct ft_mc_group *ft_mc_find(const struct net_device *bridge,\n"
          "                                      const struct br_ip *addr);\n"
          "static void ft_mc_group_free(struct ft_mc_group *g);\n"
        + "\n".join(function(source, name) for name in [
            "ft_mc_same_group",
            "ft_mc_find",
            "ft_mc_port_eligible",
            "ft_mc_port_tags",
            "ft_mc_group_free",
            "ft_mc_membership",
            "ft_mc_drop_port",
            "ft_mc_key_contested",
            "ft_mc_seen_eq",
            "ft_mc_match",
        ]))
    binary = tmp_path / "mcast_learner"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
        "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("mcast_learner.c")), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })


def test_the_handler_never_blocks_on_the_transaction():
    """The MDB handler runs holding RTNL -- switchdev_port_obj_add_deferred()
    asserts it -- and cdx_ctrl_lock_with_rtnl() states the rule those two live
    under: never wait for either lock while holding the other. So the handler
    may take ft_mc_lock and nothing else, and the hardware belongs to a worker
    that runs outside RTNL.
    """
    source = SOURCE.read_text()
    body = function(source, "ft_mc_swdev_obj")
    for forbidden in ("cdx_ft_begin", "cdx_mc_group_add", "cdx_mc_group_del",
                      "cdx_mc_group_replace", "cdx_mc_port_supported"):
        assert forbidden not in body, (
            f"{forbidden} needs the transaction; the MDB handler holds RTNL "
            f"and must not wait for it")
    # The identity check it may use is the one that answers under its own lock.
    assert "cdx_mc_port_identity" in function(source, "ft_mc_port_eligible")


def test_the_worker_never_holds_the_group_lock_across_the_transaction():
    """/proc reads the group list from inside the transaction, so a worker
    that took the transaction while holding ft_mc_lock would close a cycle
    with it. The worker snapshots under the lock, releases it, then does the
    hardware.
    """
    body = function(SOURCE.read_text(), "ft_mc_work_fn")
    unlock = body.index("mutex_unlock(&ft_mc_lock)")
    assert "cdx_ft_begin();" in body, "the worker is where the hardware happens"
    assert unlock < body.index("cdx_ft_begin();"), (
        "ft_mc_lock must be released before the transaction is taken")


def test_every_reference_the_learner_takes_is_released():
    """A group pins its bridge, every listener port, and its ingress port for
    as long as it lives -- the backend borrows them and the entry names ports
    that must not be unregistered underneath it. One free path releases all of
    them.
    """
    source = SOURCE.read_text()
    free = function(source, "ft_mc_group_free")
    for field in ("g->port[i].dev", "g->in", "g->bridge"):
        assert f"dev_put({field})" in free, f"{field} must be released"

    # And nothing else frees a group, so there is one place to get it right.
    others = [n for n in ("ft_mc_membership", "ft_mc_work_fn", "ft_mc_exit")
              if "kfree(g)" in function(source, n)]
    assert not others, f"groups must be freed only by ft_mc_group_free: {others}"


def test_exit_drains_before_the_module_text_goes_away():
    """The worker holds a pointer into this module. Unloading has to stop it
    and drain the groups, and it must do so after the switchdev chain is
    unregistered so nothing can add one while it drains.
    """
    source = SOURCE.read_text()
    exit_body = function(source, "ask_flowtable_exit")
    assert "ft_mc_exit();" in exit_body
    assert exit_body.index("unregister_switchdev_blocking_notifier") < \
        exit_body.index("ft_mc_exit();"), (
        "the chain must be gone before the groups drain")

    mc_exit = function(source, "ft_mc_exit")
    assert "cancel_work_sync(&ft_mc_work)" in mc_exit, (
        "the worker must be stopped, not merely asked to stop")
    assert "WRITE_ONCE(ft_mc_stopping, true)" in mc_exit

    # The hook is unregistered on both sides of the cancel. Registering sleeps,
    # so a worker part-way through planting one when the flag went up is only
    # actually stopped by the second call -- and a hook left on the bridge
    # chain after the module text is unmapped oopses on the next frame.
    assert mc_exit.count("ft_mc_hook_sync(false)") == 2, (
        "the hook must be unregistered before and after the work is cancelled")
    assert mc_exit.index("ft_mc_hook_sync(false)") < \
        mc_exit.index("cancel_work_sync(&ft_mc_work)") < \
        mc_exit.rindex("ft_mc_hook_sync(false)")

    sync = function(source, "ft_mc_hook_sync")
    assert "mutex_lock(&ft_mc_hook_lock)" in sync, (
        "the flag alone cannot serialize a registration that sleeps")
    assert "READ_ONCE(ft_mc_stopping)" in sync, (
        "teardown must win however the two interleave")


def test_the_vid_follows_the_bridge_rather_than_the_port():
    """A bridge that does not filter resolves every frame to VLAN zero and
    reports every MDB entry with vid zero, but the port's PVID is not zero --
    nbp_vlan_init() installs the bridge's default_pvid on enslavement whatever
    the filtering setting. Asking the port unconditionally returns 1, no
    observation ever matches a membership, and the learner is inert on the
    commonest configuration there is.
    """
    body = function(SOURCE.read_text(), "ft_mc_frame_vid")
    assert "br_vlan_enabled(bridge)" in body, (
        "a bridge that does not filter has no VLAN to resolve")
    assert body.index("br_vlan_enabled(bridge)") < \
        body.index("br_vlan_get_pvid_rcu"), (
        "the filtering test must come before the PVID lookup")


def test_a_blocked_port_group_is_not_a_listener():
    """A blocked port group is one an IGMPv3 source filter excludes this source
    for; br_forward() skips it. Installing it would deliver exactly what the
    filter excluded, and with the frame no longer reaching the bridge there is
    no software path left to correct it.
    """
    body = function(SOURCE.read_text(), "ft_mc_swdev_obj")
    assert "SWITCHDEV_OBJ_MDB_F_BLOCKED" in body, (
        "the learner must honour the bridge's source filter")


def test_the_learner_lets_go_of_a_device_that_went_away():
    """Nothing reports a group's ingress port, and a permanent MDB entry's
    delete arrives after the port has left the bridge -- del_nbp() flushes
    those from br_multicast_del_port(), after netdev_upper_dev_unlink(). Both
    would otherwise hold a reference that blocks unregistration for good.
    """
    source = SOURCE.read_text()
    netdev = function(source, "ft_netdev_event")
    assert netdev.count("ft_mc_device_gone(dev)") == 2, (
        "both the link going down and unregistration must reach the learner")

    gone = function(source, "ft_mc_device_gone")
    assert "ft_mc_drop_port(dev)" in gone, "as a listener"
    assert "g->in == dev" in gone, "as an ingress"
    assert "g->bridge == dev" in gone, "as the bridge itself"

    # And the delete that arrives too late falls back to dropping the port
    # wherever it is still listed.
    swdev = function(source, "ft_mc_swdev_obj")
    assert "ft_mc_drop_port(port)" in swdev, (
        "a delete with no master left must still release the port")
