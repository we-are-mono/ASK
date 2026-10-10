"""The typed multicast group interface, and the promises its shape makes.

None of this compiles the backend: its operations reach the FMAN hash table,
the group-id allocator and the control mutex, and a host harness that stubbed
all three would be asserting against the stubs. What is checked here is the
part a hardware run cannot show cheaply and a reader cannot be trusted to
maintain by eye -- that the contract the header states is the one the
implementation keeps.
"""

from _host_mcast_backend import (HEADER, ROOT, SOURCE, code, declarations)

import re

from _host_qos_lifecycle import (function)


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


def test_mutators_take_the_mutators_mutex():
    """dpa_control_mc.c states the rule: the three mutators and the
    interface-removal sweep run under mc_mutators_mutex. The flowtable
    transaction happens to serialise every current caller; the mutex keeps the
    invariant explicit for one that does not.
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


def test_a_listener_is_its_whole_framing_not_its_port():
    """One port may carry two copies of a group with different tags, and may
    not carry the same copy twice.

    Nothing below this interface identifies a member by its device: each
    listener gets its own external-hash entry built from its own
    encapsulation, and members[] is indexed by position. The name lookups the
    retired FCI mutators used -- Cdx_GetMcastMemberId, mcast_member_by_name --
    must not come back on this path.

    The shape matters because of the bench rather than the product: the rig
    has one LAN port with carrier and every group's other port is its ingress,
    so two tagged copies on that one port are the only way replication to
    several listeners and the chain swap can be exercised at all (A158).
    """
    body = code("cdx_mc_check")
    assert "o->vlans == l->vlans" in body and "memcmp(o->vlan, l->vlan" in body, (
        "the duplicate test must compare the whole framing, not the device")
    # And the address a copy leaves with: two devices ipmr sends through, or a
    # bridged copy beside a routed one, are two frames on one port and tags.
    assert "ether_addr_equal(o->src_mac, l->src_mac)" in body, (
        "copies that differ only in their source address are two copies")
    assert "spec->listener[jj].dev == l->dev" not in body, (
        "a port named twice with different tags is two copies, not a duplicate")
    # And the in-kernel build path still indexes its members by position.
    build = code("cdx_mc_build_listeners")
    for byname in ("Cdx_GetMcastMemberId", "mcast_member_by_name"):
        assert byname not in build, (
            f"{byname} identifies a member by name; this path must not use it")
    assert "grp->members[ii]" in build


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
    # it until a barrier completes (test_replace_frees_what_its_barrier_proves_
    # and_parks_the_rest()).
    assert "cdx_ehash_quarantine_entry(" in body, (
        "a displaced chain whose barrier failed must be quarantined")
    assert "cdx_free_exthash_mcast_members(grp)" not in body, (
        "the group's own members are the new chain, never to be released here")

    publish = code("cdx_mc_publish_chain")
    assert publish.index("wmb();") < publish.index("first_member_flow_addr ="), (
        "the new chain must be visible to FMAN before the pointer that reaches it")


def test_replace_frees_what_its_barrier_proves_and_parks_the_rest():
    """The displaced chain is out of the root entry's reach once the new one is
    published, but a walk begun before may still be inside it until a barrier
    completes. The splice's own barrier is tried first: what it proves gone goes
    straight back to the allocator, and anything parked before it with it, so
    the backlog settles at zero rather than growing by a chain per channel
    change. Only what a failed barrier leaves is parked, for the next one. Parked
    before the barrier, a record that could not be made leaked the entry for
    good even when the barrier then completed (A360). Nothing else is bound to
    release the backlog soon, so replace also drains it before building.
    """
    body = code("cdx_mc_group_replace")
    swap = body.index("grp->members[ii] = fresh->members[ii];")
    assert body.count("cdx_ehash_quarantine_drain(") == 1 and \
        body.index("cdx_ehash_quarantine_drain(") < swap, "replace must reclaim before it builds"
    # The splice's own barrier, through the file's funnel so the test image
    # can fail it, before anything displaced is parked or freed.
    barrier = body.index("if (mc_hcsync(", swap)
    assert body.index("cdx_ehash_quarantine_entry(") > barrier, (
        "nothing displaced may be parked before its barrier has been tried")
    assert "ExternalHashTableEntryFree(" not in body[:barrier], (
        "nothing displaced may be freed before its barrier has completed")
    otherwise = body.index("} else {", barrier)
    failed, completed = body[barrier:otherwise], body[otherwise:]
    completed = completed[:completed.index("\n\t}")]
    assert re.search(r"if \(old\[ii\]\.bIsValidEntry[^)]*\)\s*cdx_ehash_quarantine_entry\([^;]*"
                     r"old\[ii\]\.tbl_entry\);", failed) and "EntryFree" not in failed, (
        "a failed barrier must park every displaced entry and free none")
    assert re.search(r"if \(old\[ii\]\.bIsValidEntry[^)]*\)\s*ExternalHashTableEntryFree\("
                     r"old\[ii\]\.tbl_entry\);", completed) and \
        "cdx_ehash_quarantine_free_all();" in completed and \
        "cdx_ehash_quarantine_entry(" not in completed, (
        "a completed barrier must free the displaced entries and the backlog, and park nothing")


def test_a_withdrawn_group_parks_against_its_own_table():
    """Every parked entry records the table it left, so a waiter with no table
    of its own can issue the barrier through it. A group's members are parked
    after the delete that frees the group's hw_ct, which is where the table is
    named, so it has to be read before that delete and handed over."""
    body = code("cdx_mcast_group_destroy")
    read = body.index("->ct->td")
    assert read < body.index("delete_entry_from_classif_table("), (
        "the table must be read before the delete frees the hw_ct holding it")
    assert "mc_quarantine_members(pMcastGrpInfo, td)" in body
    members = code("mc_quarantine_members")
    assert "cdx_ehash_quarantine_entry(td," in members and "->ct" not in members, (
        "members are parked against the table they were given, not one read now")


def test_a_root_that_may_be_linked_keeps_its_listeners_for_the_restart():
    """A group whose classifier entry could not be proven unlinked may still
    replicate through its listener chain, so none of the chain may be freed or
    parked -- a parked entry goes on the next barrier, which proves nothing
    about a chain a linked root still reaches. The root itself is recorded by
    cdx_ehash_delete_entry(); every listener is recorded behind it, for the
    datapath restart to free once the root is settled, and the latch that
    brings that restart about is raised. Each listener is handed over once,
    before its slot is cleared."""
    body = code("cdx_mcast_group_destroy")
    unsynced = body.index("rc == EN_EHASH_DELETE_UNSYNCED")
    failure = body[body.index("else", body.index("mc_quarantine_members(", unsynced)):
                   body.index("if (pMcastGrpInfo->pCtEntry)")]
    assert failure.count("cdx_ehash_abandon_dependent(pMcastGrpInfo->members[ii].tbl_entry);") == 1
    assert failure.index("cdx_ehash_abandon_dependent(") < \
        failure.index("pMcastGrpInfo->members[ii].tbl_entry = NULL;"), (
            "a listener must be recorded before its slot forgets it")
    assert "cdx_ft_fatal();" in failure
    for forbidden in ("ExternalHashTableEntryFree", "cdx_ehash_quarantine_entry",
                      "cdx_free_exthash_mcast_members", "mc_quarantine_members"):
        assert forbidden not in failure, f"{forbidden} on a chain a linked root may reach"


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
    assert "cdx_mc_describe(grp, spec);" in add
    assert "grp->in_dev = spec->in;" in function(source, "cdx_mc_describe"), (
        "the pinned device must be recorded")

    # And the resolutions that follow from it: the ingress onif and the MAC
    # subscription both go through the device, and nothing falls back to the
    # name.
    root = function(source, "cdx_add_mcast_table_entry")
    assert "pMcastGrpInfo->in_dev" in root and "get_onif_by_index(" in root, (
        "the ingress onif must resolve by index from the device")
    assert "dev_mc_add(grp->in_dev," in function(source, "cdx_mcast_subscribe_ingress_mac")
    assert "dev_mc_del(grp->in_dev," in function(source, "cdx_mcast_unsubscribe_ingress_mac")
    for lookup in ("get_onif_by_name(", "dev_get_by_name("):
        assert lookup not in source, f"nothing may resolve the ingress by name ({lookup})"


def test_an_untagged_listener_overrides_nothing():
    """apply_l2_encap() refuses a description the interface walk already filled
    in, so handing it an empty override could only fail the whole group for a
    listener that asked for nothing. The flowtable's own encoder guards the
    same way.
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


def test_a_bridged_group_is_keyed_on_its_own_frames():
    """A bridge forwards a frame with the addresses it arrived with, and
    successive frames of one (S,G) can come from different senders. So a
    bridged group's root is keyed on the frame's own Ethernet pair, in the
    bridged multicast table, and every copy writes that pair back: the only
    way a listener can know the sender's address is for its root to have
    matched it. A routed group keeps the routed key and its copies take their
    oif's own address, as ipmr sends them.
    """
    check = code("cdx_mc_check")
    assert "spec->bridged && (!is_multicast_ether_addr(spec->dst_mac)" in check
    assert "!is_valid_ether_addr(spec->src_mac)" in check

    describe = code("cdx_mc_describe")
    assert "grp->mac_keyed = spec->bridged;" in describe
    assert "memcpy(grp->mac_pair, spec->dst_mac, ETH_ALEN);" in describe
    assert "memcpy(grp->mac_pair + ETH_ALEN, spec->src_mac, ETH_ALEN);" in describe

    root = code("cdx_add_mcast_table_entry")
    assert "pMcastGrpInfo->mac_keyed ? pMcastGrpInfo->mac_pair : NULL" in root
    assert "&in_encap" in root

    build = code("cdx_mc_build_listeners")
    assert "IPV4_BRIDGED_MULTICAST_TABLE" in build and "IPV6_BRIDGED_MULTICAST_TABLE" in build
    assert "frame.mac_pair = grp->mac_pair;" in build

    encoder = (ROOT / "cdx/cdx_ehash.c").read_text()
    insert = code("insert_mcast_entry_in_classif_table", encoder)
    assert "fill_mcast_mac_key(entry, mac_pair," in insert
    assert "IPV6_BRIDGED_MULTICAST_TABLE" in insert
    # The group's own tags are applied after the interface walk, as a flow's
    # are, and only when it names some.
    assert insert.index("dpa_get_tx_info_by_itf(") < insert.index("apply_l2_encap(info, in_encap)")
    member = code("create_exthash_entry4mcast_member", encoder)
    assert member.index("apply_l2_encap(pInsEntryInfo, encap)") < \
        member.index("mcast_member_frame(pInsEntryInfo, frame);"), (
        "the pair overrides the walk's header after the walk")


def test_one_entry_per_classifier_key_not_per_address_pair():
    """The root is hashed on the ingress port, the address pair and, in the
    bridged table, the Ethernet pair. Groups that differ in any of those are
    entries the classifier tells apart and may coexist. A difference in
    ingress tags alone does not make a second key, because the key names no
    VLAN. Every group pins its ingress device, so there is no nameless group
    for the address pair alone to collide with.
    """
    taken = code("cdx_mc_key_taken")
    assert "tmp->in_dev != grp->in_dev || tmp->mac_keyed != grp->mac_keyed" in taken
    assert "memcmp(tmp->mac_pair, grp->mac_pair, sizeof(grp->mac_pair))" in taken
    assert "!tmp->in_dev" not in taken and "!grp->in_dev" not in taken
    assert "in_vlan" not in taken
    assert "cdx_mc_key_taken(grp)" in code("cdx_mc_group_add")
    assert "GetMcastGrpId(" not in code("cdx_mc_group_add")

    # And a replace may change neither the pair nor the tags: both belong to
    # the root, which a chain swap leaves where it is.
    same = code("cdx_mc_same_key")
    assert "described.mac_keyed != grp->mac_keyed" in same
    assert "memcmp(described.in_vlan, grp->in_vlan, sizeof(grp->in_vlan))" in same
