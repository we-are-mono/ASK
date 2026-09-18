"""The typed multicast group interface, and the promises its shape makes.

None of this compiles the backend: its operations reach the FMAN hash table,
the group-id allocator and the control mutex, and a host harness that stubbed
all three would be asserting against the stubs. What is checked here is the
part a hardware run cannot show cheaply and a reader cannot be trusted to
maintain by eye -- that the contract the header states is the one the
implementation keeps.
"""

from pathlib import Path
import re

from test_qos_lifecycle import function

ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / "cdx/cdx_mcast_backend.h"
SOURCE = ROOT / "cdx/dpa_control_mc.c"


def declarations(source):
    """Source with its comments removed. The prose is allowed to name the
    legacy vocabulary -- explaining what this interface replaces is most of
    what it says -- but none of it may appear in a declaration. Every ordering
    assertion below goes through this too: a comment that mentions a call is
    not that call, and matching one silently inverts the check.
    """
    return re.sub(r"/\*.*?\*/", "", source, flags=re.S)


def code(name, source=None):
    """One function's body, comments stripped."""
    return declarations(function(source or SOURCE.read_text(), name))


def test_interface_is_typed():
    """No wire message, no interface-name string, no FCI vocabulary. The point
    of the interface is that a caller holding netdevs and a conntrack-shaped
    address describes a group without going through a control plane that only
    exists to carry CMM's messages.
    """
    header = declarations(HEADER.read_text())

    for forbidden in ("MC4Command", "MC6Command", "MC4Output", "IF_NAME_SIZE",
                      "output_device_str", "input_device_str", "CMD_MC4"):
        assert forbidden not in header, f"{forbidden} must not cross this interface"

    spec = re.search(r"struct cdx_mc_group_spec \{(.*?)\n\};", header, re.S).group(1)
    assert "struct net_device *in;" in spec
    assert "union nf_inet_addr src;" in spec and "union nf_inet_addr dst;" in spec
    assert "struct cdx_mc_listener listener[CDX_MC_MAX_LISTENERS];" in spec

    listener = re.search(r"struct cdx_mc_listener \{(.*?)\n\};", header, re.S).group(1)
    assert "struct net_device *dev;" in listener
    assert "struct cdx_ft_vlan vlan[CDX_FT_VLAN_MAX];" in listener


def test_every_operation_runs_in_the_flowtable_transaction():
    """A group and a flow reach the same classifier through the same control
    mutex, so the group interface takes no lock of its own and asserts the
    caller holds that one -- the discipline cdx_ipsec_backend.h states and for
    the same reason.
    """
    source = SOURCE.read_text()
    for name in ("cdx_mc_group_add", "cdx_mc_group_replace", "cdx_mc_group_del"):
        assert "cdx_ft_assert_held();" in function(source, name), (
            f"{name} must assert the flowtable transaction is held")


def test_mutators_serialise_against_the_fci_handlers():
    """dpa_control_mc.h states the rule: the three mutators run under
    mc_mutators_mutex, and a caller that does not arrive through the command
    dispatcher takes it explicitly. These are exactly such callers.
    """
    source = SOURCE.read_text()
    for name in ("cdx_mc_group_add", "cdx_mc_group_replace", "cdx_mc_group_del"):
        body = function(source, name)
        assert body.count("mutex_lock(&mc_mutators_mutex)") == 1, name
        assert body.count("mutex_unlock(&mc_mutators_mutex)") >= 1, name


def test_a_source_is_required_and_link_local_is_refused():
    """The classifier composes {portid, saddr, daddr, protocol} into an external
    hash, so a wildcard source cannot match -- it would change the hash rather
    than widen it. And link-local scope carries IGMP, MLD and the querier the
    bridge's own snooping depends on, so replicating it in hardware would take
    the membership protocol away from the source of truth for every group here.
    """
    body = code("cdx_mc_check_group")

    assert "!spec->src.ip" in body, "an IPv4 group must require a source"
    assert "ipv6_addr_any(&spec->src.in6)" in body, "an IPv6 group must require a source"
    assert "0xe0000000" in body, "an IPv4 group must be inside 224.0.0.0/4"
    assert "0xffffff00" in body, "224.0.0.0/24 must be refused"
    assert "IPV6_ADDR_SCOPE_LINKLOCAL" in body, "IPv6 link-local scope must be refused"


def test_a_group_is_all_or_nothing():
    """A matched frame never reaches the bridge, so a listener the hardware did
    not take on does not fall back to software -- it stops receiving. There is
    no partial group to offer, which is why a listener that cannot be carried
    fails the whole spec rather than being dropped from it.
    """
    body = code("cdx_mc_check")
    # Any unsupported listener refuses the spec; nothing is skipped or trimmed.
    assert "return -EOPNOTSUPP;" in body
    assert "continue;" not in body, (
        "a listener must never be skipped -- a partial group is a broken one")


def test_replace_keeps_the_key_in_the_classifier():
    """Delete-then-add would take the group's key out of the table between the
    two, so every remaining listener would see a gap because a different
    listener came or went -- and in an IPTV deployment membership changes
    whenever anyone changes channel. The set is exchanged by repointing the
    root entry's REPLICATE chain instead.
    """
    body = code("cdx_mc_group_replace")

    assert "cdx_mc_publish_chain(" in body
    assert "delete_entry_from_classif_table" not in body and \
           "cdx_mcast_group_destroy" not in body, (
        "replace must not take the group's key out of the classifier")
    # The old chain is unreachable from the root but a walk can still be inside
    # it, which is what the quarantine is for.
    assert "cdx_ehash_quarantine_entry(" in body, (
        "the displaced chain must be quarantined, not freed")
    assert "cdx_free_exthash_mcast_members(grp)" not in body, (
        "the displaced chain must never be released outright")

    publish = code("cdx_mc_publish_chain")
    assert publish.index("wmb();") < publish.index("first_member_flow_addr ="), (
        "the new chain must be visible to FMAN before the pointer that reaches it")


def test_replace_drains_what_it_parks():
    """The displaced chain is parked, and in this ownership mode nothing else
    would ever release it: the FCI mcast mutators never run, and cdx_ft_hw_del()
    frees entries directly without touching the quarantine. Membership changes
    whenever anyone changes channel, so an undrained backlog grows by a chain
    per change until the entry pool is exhausted -- which fails every classifier
    insert, not just multicast.
    """
    body = code("cdx_mc_group_replace")
    assert body.count("cdx_ehash_quarantine_drain(") == 2, (
        "replace must reclaim before parking and drain what it parked")
    assert body.index("cdx_ehash_quarantine_entry(") < body.rindex(
        "cdx_ehash_quarantine_drain("), (
        "the drain that settles the backlog must follow the parking")


def test_a_group_is_keyed_on_its_device_not_its_name():
    """Nothing in cdx handles NETDEV_CHANGENAME. A group keyed on the ingress
    interface's name would, after a rename, stop recognising itself: every
    replace would return -EINVAL and the listener set would be frozen for good,
    with delete-and-add the only recovery -- which is the gap replace exists to
    avoid.
    """
    source = SOURCE.read_text()
    key = function(source, "cdx_mc_same_key")
    assert "in_dev" in key, "the ingress must be compared as a device"
    assert "ucIngressIface" not in key, (
        "the ingress must not be compared by name")

    add = function(source, "cdx_mc_group_add")
    assert "grp->in_dev = spec->in;" in add, "the pinned device must be recorded"

    # And the resolutions that follow from it: the ingress onif and the MAC
    # subscription both prefer the device when the group carries one.
    root = function(source, "cdx_add_mcast_table_entry")
    assert "pMcastGrpInfo->in_dev" in root and "get_onif_by_index(" in root, (
        "the ingress onif must resolve by index when a device is held")
    ingress = function(source, "cdx_mcast_ingress_dev")
    assert "grp->in_dev" in ingress and "dev_get_by_name(" in ingress, (
        "the MAC subscription must prefer the device and fall back to the name")


def test_an_untagged_listener_overrides_nothing():
    """apply_l2_encap() refuses a description the interface walk already filled
    in, and a DSCP-to-PCP egress map fills one in -- it pushes a priority tag on
    a plain physical port. Handing it an empty override would fail the whole
    group for a listener that asked for nothing. The flowtable's own encoder
    guards the same way.
    """
    body = code("cdx_mc_listener_entry")
    assert "listener->vlans ? &encap : NULL" in body, (
        "an untagged listener must be given no encapsulation override")


def test_the_two_listener_bounds_are_pinned_together():
    """CDX_MC_MAX_LISTENERS bounds what a caller may ask for; it indexes an
    array sized by MC_MAX_LISTENERS_PER_GROUP, in a different header. Raising
    the public one alone is a heap overflow of struct mcast_group_info.
    """
    source = SOURCE.read_text()
    assert re.search(
        r"static_assert\(\s*CDX_MC_MAX_LISTENERS\s*==\s*MC_MAX_LISTENERS_PER_GROUP",
        source), "the two listener bounds must be pinned to each other"


def test_the_members_swap_takes_the_bucket_lock():
    """members[] is what the per-bucket spinlock protects -- both legacy
    mutators take it around exactly this mutation and the file's header states
    the convention. The opcode-parameter store does not need it and does not
    take it. Parking happens after the lock is dropped, because
    cdx_ehash_quarantine_entry() allocates.
    """
    body = code("cdx_mc_group_replace")
    assert "spin_lock(lock);" in body and "spin_unlock(lock);" in body
    assert body.index("spin_unlock(lock);") < body.index(
        "cdx_ehash_quarantine_entry("), (
        "entries must be parked outside the spinlock -- parking allocates")


def test_a_failed_publish_destroys_nothing():
    """The caller disposes of the old chain on the strength of the swap having
    happened, so a publish that could not happen must say so rather than
    returning quietly and leaving the group with a listener set the hardware
    was never told about.
    """
    source = SOURCE.read_text()
    assert re.search(r"static int cdx_mc_publish_chain\(", source), (
        "publishing must be able to fail")
    body = function(source, "cdx_mc_group_replace")
    assert "rc = cdx_mc_publish_chain(" in body, "its result must be taken"
    assert body.index("rc = cdx_mc_publish_chain(") < body.index(
        "cdx_ehash_quarantine_entry("), (
        "nothing may be destroyed before the swap is known to have happened")


def test_the_group_id_is_released_once():
    """cdx_free_exthash_mcast_members() hands the id back itself, so the arms of
    cdx_mc_program() that reach it leave grpid -1. Releasing it again would free
    a slot a later add may already hold -- harmless only while two mutexes
    happen to be held across both.
    """
    source = SOURCE.read_text()
    add = function(source, "cdx_mc_group_add")
    assert "if (grp->grpid != -1)" in add, (
        "the id must be released only if it is still held")
    for name in ("cdx_mc_build_listeners", "cdx_mc_program"):
        body = function(source, name)
        if "cdx_free_exthash_mcast_members" in body:
            assert "grp->grpid = -1;" in body, (
                f"{name} must record that it gave the id back")


def test_replace_refuses_a_different_key():
    """A different key is a different entry in a different hash bucket. That is
    an add and a delete, not a replacement, and silently treating it as one
    would leave the old group installed forever.
    """
    source = SOURCE.read_text()
    assert "cdx_mc_same_key(grp, spec)" in function(source, "cdx_mc_group_replace")
    key = code("cdx_mc_same_key", source)
    for field in ("in_dev", "ipv4_saddr", "ipv4_daddr",
                  "ipv6_saddr", "ipv6_daddr", "mctype"):
        assert field in key, f"{field} is part of the key and must be compared"
