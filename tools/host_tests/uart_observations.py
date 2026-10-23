"""Compact evidence must still check every flow, including unchanged counts."""

import json
import gzip

import pytest

from askd_agent.observe import STATE, Snapshots, read_state


def proc_dir(tmp_path, **levels):
    """A /proc/ask_flowtable with these levels in its status, and every other
    file but the flows empty; the caller writes the flows."""
    proc = tmp_path / "proc"
    proc.mkdir()
    for name in STATE:
        (proc / name).write_text("")
    (proc / "status").write_text("".join(f"{k + ':':<36}{v:>12}\n" for k, v in levels.items()))
    return proc


def test_state_carries_the_module_parameters(tmp_path):
    """procfs repeats no module parameter; a state reads them beside the files,
    a bool's Y and N as 1 and 0, and leaves out one whose module is not
    loaded."""
    proc = proc_dir(tmp_path, entries=0, bindings=2)
    params = tmp_path / "params"
    params.mkdir()
    (params / "multicast").write_text("Y\n")
    (params / "flowtable_observe").write_text("N\n")
    (params / "qos_mark_mask").write_text("240\n")
    parameters = {"mcast_enabled": params / "multicast", "observe": params / "flowtable_observe",
                  "qos_mark_mask": params / "qos_mark_mask", "transit": params / "absent"}
    state = read_state(summary=True, proc=proc, parameters=parameters)
    assert state["bindings"] == 2 and state["mcast_enabled"] == 1 and state["observe"] == 0
    assert state["qos_mark_mask"] == 0xf0 and "transit" not in state
    with pytest.raises(ValueError, match="unexpected"):
        (proc / "stats").write_text("installs 3\n")  # the old layout
        read_state(summary=True, proc=proc, parameters={})


def test_full_table_comparison_detects_hidden_identity_changes(tmp_path):
    count = 16384
    proc = proc_dir(tmp_path, entries=count * 2, handle_refs=count * 2, neighbour_refs=count * 2)
    path = proc / "flows"
    config = dict(lan="192.0.2.2", wan="198.51.100.2", public="198.51.100.1",
                  lan_if="lan", wan_if="wan", base=20000, dport=48271,
                  count=count, survivors=1)

    def write(*, changed=False, missing=False, packets=10):
        with path.open("w") as stream:
            for ident in range(count):
                proto, port = (6 if ident & 1 else 17), 20000 + ident // 2
                for ingress, src, dst in (
                    ("lan", f"192.0.2.2:{port}", "198.51.100.2:48271"),
                    ("wan", "198.51.100.2:48271", f"198.51.100.1:{port}"),
                ):
                    cookie = f"{ident}-{ingress}"
                    if ident == 0 and ingress == "lan":
                        if changed:
                            cookie = "different-generation"
                        if missing:
                            src = "192.0.2.99:20000"
                    stream.write(f"flow cookie={cookie} in={ingress} proto={proto} src={src} dst={dst} "
                                 f"packets={packets} bytes=2560 mtu=1500 new_src=198.51.100.1:{port}\n")

    store = Snapshots(tmp_path, proc)
    try:
        store.configure(config)
        write()
        first = store.capture({})
        # The evidence is every file as read, in the order it was read.
        assert gzip.decompress((tmp_path / f"snapshot-{first['snapshot']}.txt.gz").read_bytes()).decode() == \
            "".join((proc / name).read_text() for name in STATE)
        assert first["flow_count"] == 32768 and len(json.dumps(first)) < 1024
        assert first["entries"] == first["handle_refs"] == 32768
        assert store.check({"snapshot": first["snapshot"]})["missing_count"] == 0
        summary = read_state(summary=True, proc=proc)
        assert summary["flows"] == [] and summary["entries"] == 32768
        with pytest.raises(ValueError, match="local snapshot"):
            read_state(proc=proc)

        write(changed=True, packets=11)
        second = store.capture({})
        result = store.compare({"before": first["snapshot"], "after": second["snapshot"]})
        assert result["checked"] == 32768
        assert result["missing_count"] == result["unexpected_count"] == 0
        assert result["regenerated_count"] == result["unchanged_errors"] == 1
        assert result["regenerated"] == [("lan", "17", "192.0.2.2:20000", "198.51.100.2:48271")]
        assert len(json.dumps(result)) < 1024

        write(missing=True)
        third = store.capture({})
        result = store.check({"snapshot": third["snapshot"]})
        assert result["checked"] == 32768
        assert result["missing_count"] == result["unexpected_count"] == 1
        store.release({"snapshot": first["snapshot"]})
        with pytest.raises(ValueError, match="unknown"):
            store.compare({"before": first["snapshot"], "after": third["snapshot"]})
    finally:
        store.reset()


@pytest.mark.parametrize("reply_port,clean", [(14247, True), (14248, False)])
def test_check_follows_a_remapped_masquerade_port(tmp_path, reply_port, clean):
    """MASQUERADE keeps a flow's source port unless another conntrack already
    holds that reply tuple, and then picks another one. A flow whose two
    directions agree on the port it was given is the workload's flow; one
    whose reply direction names some other port is not."""
    proc = proc_dir(tmp_path, entries=8)
    path = proc / "flows"
    config = dict(lan="192.0.2.2", wan="198.51.100.2", public="198.51.100.1",
                  lan_if="lan", wan_if="wan", base=20000, dport=48271, count=4)
    with path.open("w") as stream:
        for ident in range(4):
            proto, port = (6 if ident & 1 else 17), 20000 + ident // 2
            given, reply = (14247, reply_port) if ident == 2 else (port, port)
            stream.write(f"flow cookie={ident}-lan in=lan proto={proto} src=192.0.2.2:{port} "
                         f"dst=198.51.100.2:48271 packets=1 bytes=1 mtu=1500 "
                         f"new_src=198.51.100.1:{given}\n")
            stream.write(f"flow cookie={ident}-wan in=wan proto={proto} src=198.51.100.2:48271 "
                         f"dst=198.51.100.1:{reply} packets=1 bytes=1 mtu=1500 "
                         f"new_src=198.51.100.2:48271\n")
    store = Snapshots(tmp_path, proc)
    try:
        store.configure(config)
        before = store.capture({})["snapshot"]
        result = store.check({"snapshot": before})
        assert result["translation_errors"] == 0, result
        if clean:
            assert result["missing_count"] == result["unexpected_count"] == 0, result
            # Retiring the remapped flow by its identity is retiring both of
            # its directions, whichever port it was given.
            rows = [line for line in path.read_text().splitlines()
                    if "proto=17 src=192.0.2.2:20001 " not in line and "dst=198.51.100.1:14247" not in line]
            path.write_text("\n".join(rows) + "\n")
            after = store.capture({})["snapshot"]
            result = store.compare({"before": before, "after": after, "exclude_ids": [2]})
            assert result["missing_count"] == 2 and result["unchanged_errors"] == 0, result
        else:
            assert result["missing"] == [("wan", "17", "198.51.100.2:48271", "198.51.100.1:20001")], result
            assert result["unexpected"] == [("wan", "17", "198.51.100.2:48271", "198.51.100.1:14248")], result
    finally:
        store.reset()


@pytest.mark.parametrize("source,destination", [("192.0.2.2", "198.51.100.2"),
                                                ("fd00:1::2", "fd00:2::2")])
async def test_local_deletion_batch_checks_every_ack(monkeypatch, source, destination):
    import asyncio
    import errno
    import socket
    import struct
    from types import SimpleNamespace
    import _flowtable_capacity as capacity
    from askd_agent import agent

    requests = []
    failure = None

    async def netlink(body, state):
        requests.append(body)
        payload = bytes.fromhex(body["body_hex"])
        family = socket.AF_INET6 if ":" in source else socket.AF_INET
        assert payload[0] == family and socket.inet_pton(family, source) in payload
        assert body["protocol"] == 12 and body["nlmsg_type"] == 0x102 and body["nlmsg_flags"] == 5
        error = failure if failure is not None else (-errno.ENOENT if len(requests) == 8 else 0)
        return {"reply_hex": struct.pack("=IHHIIi", 20, 2, 0, 1, 0, error).hex()}

    async def python(console, source, **kwargs):
        def run():
            output = []
            exec(source, {"print": output.append})
            return {"stdout": "\n".join(output)}
        return await asyncio.to_thread(run)

    monkeypatch.setattr(agent, "netlink_send", netlink)
    monkeypatch.setattr(capacity, "console_python", python)
    monkeypatch.setattr(capacity.Console, "target", lambda: None)
    rig = SimpleNamespace(lan_ip=source)
    assert await capacity.delete_udp(rig, list(range(20000, 20128)),
                                     destination=destination, allow_missing=True) == 1
    assert len(requests) == 128
    for failure, allow_missing in ((-errno.ENOENT, False), (-errno.EPERM, True)):
        with pytest.raises(AssertionError):
            await capacity.delete_udp(rig, [20000], destination=destination, allow_missing=allow_missing)
