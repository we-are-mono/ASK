"""Compact evidence must still check every flow, including unchanged counts."""

import json
import gzip

import pytest

from askd_agent.observe import Snapshots, read_state


def test_full_table_comparison_detects_hidden_identity_changes(tmp_path):
    path = tmp_path / "flowtable"
    count = 16384
    config = dict(lan="192.0.2.2", wan="198.51.100.2", public="198.51.100.1",
                  lan_if="lan", wan_if="wan", base=20000, dport=48271,
                  count=count, survivors=1)

    def write(*, changed=False, missing=False, packets=10):
        with path.open("w") as stream:
            stream.write(f"entries {count * 2}\nhandle_refs {count * 2}\nneighbour_refs {count * 2}\n")
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

    store = Snapshots(tmp_path, path)
    try:
        store.configure(config)
        write()
        first = store.capture({})
        assert gzip.decompress((tmp_path / f"snapshot-{first['snapshot']}.txt.gz").read_bytes()).decode() == path.read_text()
        assert first["flow_count"] == 32768 and len(json.dumps(first)) < 1024
        assert store.check({"snapshot": first["snapshot"]})["missing_count"] == 0
        assert read_state(summary=True, path=path)["flows"] == []
        with pytest.raises(ValueError, match="local snapshot"):
            read_state(path=path)

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
    path = tmp_path / "flowtable"
    config = dict(lan="192.0.2.2", wan="198.51.100.2", public="198.51.100.1",
                  lan_if="lan", wan_if="wan", base=20000, dport=48271, count=4)
    with path.open("w") as stream:
        stream.write("entries 8\n")
        for ident in range(4):
            proto, port = (6 if ident & 1 else 17), 20000 + ident // 2
            given, reply = (14247, reply_port) if ident == 2 else (port, port)
            stream.write(f"flow cookie={ident}-lan in=lan proto={proto} src=192.0.2.2:{port} "
                         f"dst=198.51.100.2:48271 packets=1 bytes=1 mtu=1500 "
                         f"new_src=198.51.100.1:{given}\n")
            stream.write(f"flow cookie={ident}-wan in=wan proto={proto} src=198.51.100.2:48271 "
                         f"dst=198.51.100.1:{reply} packets=1 bytes=1 mtu=1500 "
                         f"new_src=198.51.100.2:48271\n")
    store = Snapshots(tmp_path, path)
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
