"""A full multicast hash bucket falls back without spending another bucket's id.

Thirty-two distinct bridged groups share one real classifier bucket. The next
group must remain in software beside those residents, a carried control group
and a live discard in other buckets. Its bounded retries must release their
temporary group ids without evicting that discard. Once a resident leaves, a
fresh membership lets the refused stream use the vacancy on the same boot.
"""
from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack, ExitStack
import ipaddress

from _ehash_bucket import MCAST_MASK, bucket, crowded_mcast_ipv4, mcast_ipv4_key
from _flowtable_service_multicast_leave import FILTER_TIMERS
from _mcast_windows import (COUNT, bridge_settings, delivered, mcast_rows, members,
                            moved, packets, quiet, stream, summary)
from _topology import LAN_NIC, TARGET_LAN_IF, TARGET_WAN_IF
from flowtable_service_multicast_discard_capacity import (Fill, HOLDING, filled,
                                                         fill_memberships)


PREFIX = "239.79.0.0/16"
BUCKET_KEYS = 32
RETRIES = 4
# More than two five-second refreshes after the last permitted attempt.
PLATEAU = 11


async def test_full_bucket_preserves_other_groups_and_recovers(multicast_rig, mcast_bridge):
    r = multicast_rig
    crowded = crowded_mcast_ipv4(BUCKET_KEYS + 1, PREFIX)
    residents, overflow = crowded[:-1], crowded[-1]

    def modeled(group, source=bytes(4), mac=bytes(6)):
        # Every frame has the same physical ingress: its port id shifts all
        # buckets equally, so zero proves equality and separation alike.
        return bucket(mcast_ipv4_key(0, mac, source, ipaddress.ip_address(group).packed),
                      MCAST_MASK)

    occupied = {modeled(g) for g in crowded}
    assert len(occupied) == 1, crowded
    others = []
    for address in ipaddress.ip_network(PREFIX).hosts():
        group = str(address)
        index = modeled(group)
        if index not in occupied:
            others.append(group)
            occupied.add(index)
            if len(others) == 2:
                break
    assert len(others) == 2, occupied
    control, discard = others
    owned = crowded + others
    carried = residents + [control]
    configs = {g: stream(4, g, hops=64) for g in owned}
    source = configs[overflow]["source"]
    port = f"{TARGET_LAN_IF}/0"

    def row(state, group):
        rows = mcast_rows(state, group)
        assert len(rows) <= 1, (group, rows)
        return rows[0] if rows else None

    def has_state(state, group, wanted):
        found = row(state, group)
        if found is None or found["state"] != wanted:
            return False
        # A membership-only row is pending-source until traffic teaches its
        # key; validate that key once the expected learned state is reached.
        assert found["src"] == source and found["in"] == TARGET_WAN_IF, found
        assert found["br"] == mcast_bridge, found
        key = mcast_ipv4_key(0, bytes(6), bytes(4), ipaddress.ip_address(group).packed)
        assert found["dmac"] == key[1:7].hex(":"), found
        return True

    def installed(state, groups):
        return all(has_state(state, g, "installed") and members(row(state, g), "ports") == {port}
                   for g in groups)

    def unchanged(before, after, groups):
        for group in groups:
            old, new = row(before, group), row(after, group)
            assert old is not None and new is not None, (group, old, new)
            assert {k: v for k, v in old.items() if k not in ("packets", "bytes")} == \
                   {k: v for k, v in new.items() if k not in ("packets", "bytes")}, (old, new)
            assert packets(new) >= packets(old), (old, new)

    def standing(before, after, groups):
        assert installed(after, groups), summary(after)
        assert has_state(after, discard, "discarding"), summary(after)
        assert members(row(after, discard), "ports") == set(), row(after, discard)
        assert after["mcast_group_ids4"] == after["mcast_installed"] == len(groups) + 1, summary(after)
        assert after["mcast_discarding"] == 1, summary(after)
        assert after["mcast_discards_evicted"] == before["mcast_discards_evicted"], summary(after)
        assert after["quarantine"] == after["fatal"] == 0, summary(after)
        unchanged(before, after, groups + [discard])

    async def hardware_windows(groups, baseline, label):
        # Captures start sequentially and have a finite lifetime. Four per
        # window keeps the first alive through setup; unmeasured residents
        # still receive keepalives, which the measured rows must not count.
        for start in range(0, len(groups), 4):
            measured = groups[start:start + 4]
            with Fill(4, [g for g in groups if g not in measured], r.wire):
                window = await r.window([configs[g] for g in measured], [(r.lan, {LAN_NIC: None})],
                                        ingress=TARGET_WAN_IF, label=f"bucket-{label}-{start}")
            for group in measured:
                assert delivered(window, configs[group], LAN_NIC), (group, window)
                assert moved(window, lambda s, g=group: row(s, g)) == COUNT, (group, window)
            assert window["stream_cpu"] == 0, window
            standing(baseline, window["after"], groups)
            assert window["after"]["mcast_install_errors"] == baseline["mcast_install_errors"], \
                summary(window["after"])

    async with AsyncExitStack() as kept_quiet:
        await kept_quiet.enter_async_context(bridge_settings(r, mcast_bridge, **FILTER_TIMERS))
        await kept_quiet.enter_async_context(quiet(r, [PREFIX]))
        empty = await r.settle(lambda s: s["mcast_group_ids4"] == s["mcast_installed"] == 0,
                               "no multicast entries before the bucket fill", timeout=30)
        assert empty["mcast_group_id_slots"] > len(owned), summary(empty)

        async with AsyncExitStack() as stack:
            await stack.enter_async_context(filled(r, mcast_bridge, owned))
            sentinel = stack.enter_context(Fill(4, [discard], r.wire))
            sentinel.period = HOLDING
            with ExitStack() as senders:
                senders.enter_context(Fill(4, carried, r.wire))
                full = await r.settle(lambda s: installed(s, carried + [discard]),
                                      "32 collision residents and two unrelated entries", timeout=30)
                source_bytes = ipaddress.ip_address(source).packed
                source_macs = {row(full, g)["smac"] for g in carried + [discard]}
                assert len(source_macs) == 1, source_macs
                mac = bytes.fromhex(source_macs.pop().replace(":", ""))
                assert len({modeled(g, source_bytes, mac) for g in crowded}) == 1
                assert len({modeled(g, source_bytes, mac) for g in (residents[0], control, discard)}) == 3

                await fill_memberships(r, mcast_bridge, [discard], add=False)
                full = await r.settle(lambda s: has_state(s, discard, "discarding"),
                                      "unrelated discard installed before overflow")
                standing(full, full, carried)
                assert full["mcast_install_errors"] == empty["mcast_install_errors"], summary(full)
                assert full["mcast_discards_evicted"] == empty["mcast_discards_evicted"], summary(full)

                with Fill(4, [overflow], r.wire):
                    refused = await r.settle(lambda s: has_state(s, overflow, "refused-failed"),
                                             "bucket overflow exhausted its bounded retries", timeout=30)
                    attempts = refused["mcast_install_errors"] - full["mcast_install_errors"]
                    assert 1 <= attempts <= RETRIES, summary(refused)
                    standing(full, refused, carried)
                    assert packets(row(refused, overflow)) == 0, row(refused, overflow)

                    await asyncio.sleep(PLATEAU)
                    held = await r.proc()
                    standing(refused, held, carried)
                    assert has_state(held, overflow, "refused-failed"), summary(held)
                    assert held["mcast_install_errors"] == refused["mcast_install_errors"], summary(held)
                    for group in carried + [discard]:
                        assert packets(row(held, group)) > packets(row(refused, group)), group

                    # The multicast key has no UDP ports: the fill's separate
                    # port avoids the CPU counter, but shares classifier hits.
                    senders.close()
                    await hardware_windows(carried, held, "full")
                    window = await r.window([configs[overflow]], [(r.lan, {LAN_NIC: None})],
                                            ingress=TARGET_WAN_IF, label="bucket-software-overflow")
                    assert delivered(window, configs[overflow], LAN_NIC), window
                    assert window["stream_cpu"] == COUNT, window
                    assert moved(window, lambda s: row(s, overflow)) == 0, window
                    assert has_state(window["after"], overflow, "refused-failed"), summary(window["after"])
                    standing(held, window["after"], carried)
                    assert window["after"]["mcast_install_errors"] == held["mcast_install_errors"], \
                        summary(window["after"])

                victim, survivors = residents[0], residents[1:] + [control]
                senders.enter_context(Fill(4, survivors, r.wire))
                # The idle victim's discard must retire before there is room.
                # Free it first: MDB notifications are deferred, so removing
                # the failed membership could briefly derive a discard before
                # the worker hears that nothing names that flow any more.
                await fill_memberships(r, mcast_bridge, [victim], add=False)
                vacant = await r.settle(lambda s: row(s, victim) is None
                                       and has_state(s, overflow, "refused-failed")
                                       and s["mcast_group_ids4"] == len(survivors) + 1,
                                       "one bucket vacancy with the overflow still refused", timeout=20)
                standing(held, vacant, survivors)
                assert vacant["mcast_install_errors"] == held["mcast_install_errors"], summary(vacant)

                # Observe removal before rejoining: a delete/add coalesced by
                # the worker would retain the old, exhausted retry budget.
                await fill_memberships(r, mcast_bridge, [overflow], add=False)
                reset = await r.settle(lambda s: row(s, overflow) is None
                                      and s["mcast_group_ids4"] == len(survivors) + 1,
                                      "failed membership and any temporary discard retired", timeout=20)
                standing(vacant, reset, survivors)
                assert reset["mcast_install_errors"] == held["mcast_install_errors"], summary(reset)
                await fill_memberships(r, mcast_bridge, [overflow], add=True)
                with Fill(4, [overflow], r.wire):
                    recovered = await r.settle(lambda s: installed(s, survivors + [overflow]),
                                               "overflow admitted into the vacant bucket", timeout=15)
                recovered_groups = survivors + [overflow]
                standing(recovered, recovered, recovered_groups)
                unchanged(held, recovered, survivors + [discard])
                assert recovered["mcast_install_errors"] == held["mcast_install_errors"], summary(recovered)
                senders.close()
                await hardware_windows(recovered_groups, recovered, "recovered")
                final = await r.proc()
                assert row(final, victim) is None, summary(final)
                assert final["mcast_discards_evicted"] == full["mcast_discards_evicted"], summary(final)
                r.record("mcast-bucket-admission", {
                    "crowded": crowded, "control": control, "discard": discard,
                    "bucket": modeled(overflow, source_bytes, mac), "attempts": attempts,
                    "full": summary(full), "refused": summary(refused), "held": summary(held),
                    "vacant": summary(vacant), "reset": summary(reset),
                    "recovered": summary(recovered), "final": summary(final)})

        drained = await r.settle(lambda s: s["mcast_group_ids4"] == s["mcast_installed"] == 0
                                 and not any(mcast_rows(s, g) for g in owned),
                                 "bucket test entries and group ids returned", timeout=30)
        assert drained["quarantine"] == drained["fatal"] == 0, summary(drained)
        assert drained["mcast_discards_evicted"] == empty["mcast_discards_evicted"], summary(drained)
