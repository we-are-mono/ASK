"""Local flowtable observations. Full-table comparisons never cross the UART."""

import asyncio
import gzip
import itertools
from pathlib import Path
import sqlite3
import threading
import time

TABLE = Path("/proc/cdx_flowtable")
ROW_NAMES = {"flow": "flows", "session": "sessions", "vlan": "vlans",
             "tunnel": "tunnels", "mcast": "mcast", "mroute": "mroute"}


def empty():
    return {name: [] for name in ROW_NAMES.values()}


def line_into(state, line):
    kind, _, rest = line.strip().partition(" ")
    if kind in ROW_NAMES:
        state[ROW_NAMES[kind]].append(dict(item.split("=", 1) for item in rest.split()))
    else:
        key, value = line.split()
        state[key] = int(value) if value.isdecimal() else value


def read_state(*, summary=False, path=TABLE):
    result = empty()
    with path.open() as stream:
        for line in stream:
            if summary and line.startswith("flow "):
                break
            line_into(result, line)
            if len(result["flows"]) > 2048:
                raise ValueError("large flowtable requires a local snapshot")
    return result


class Snapshots:
    """Disk-backed rows keep large Python object graphs off the test workload.

    SQLite indexes the columns used by capacity/churn assertions, with a 2 MiB
    page cache. Gzip files retain the complete raw rows for failure diagnosis.
    """

    def __init__(self, root, path=TABLE):
        self.path = path
        self.root = root
        self.db = sqlite3.connect(root / "flows.sqlite", check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=MEMORY")
        self.db.execute("PRAGMA cache_size=-2048")
        self.db.execute("""CREATE TABLE flow (
            shot INTEGER, ingress TEXT, proto TEXT, src TEXT, dst TEXT,
            cookie TEXT, packets INTEGER, bytes INTEGER, mtu INTEGER, new_src TEXT,
            PRIMARY KEY (shot, ingress, proto, src, dst)) WITHOUT ROWID""")
        self.sequence = itertools.count(1)
        self.headers = {}
        self.lock = threading.Lock()
        self.workload = None
        self.active = set()

    def capture(self, body):
        if len(self.headers) >= 12:
            raise ValueError("release old flow snapshots before taking another")
        ident = next(self.sequence)
        header = empty()
        count = total = 0

        def rows(raw):
            nonlocal count, total
            with self.path.open() as stream:
                for line in stream:
                    total += len(line)
                    if total > 32 << 20:
                        raise ValueError("flowtable exceeds snapshot budget")
                    raw.write(line)
                    if not line.startswith("flow "):
                        line_into(header, line)
                        continue
                    row = dict(item.split("=", 1) for item in line.split()[1:])
                    count += 1
                    yield (ident, *(row[k] for k in ("in", "proto", "src", "dst", "cookie")),
                           int(row["packets"]), int(row["bytes"]), int(row["mtu"]), row["new_src"])

        started = time.monotonic()
        evidence = self.root / f"snapshot-{ident}.txt.gz"
        try:
            with gzip.open(evidence, "wt", compresslevel=1) as raw, self.db:
                self.db.executemany("INSERT INTO flow VALUES (?,?,?,?,?,?,?,?,?,?)", rows(raw))
        except BaseException:
            evidence.unlink(missing_ok=True)
            raise
        header.pop("flows")
        header.update(snapshot=ident, flow_count=count, read_seconds=time.monotonic() - started)
        self.headers[ident] = header
        return dict(header)

    def release(self, body):
        ident = int(body["snapshot"])
        with self.db:
            self.db.execute("DELETE FROM flow WHERE shot=?", (ident,))
        del self.headers[ident]
        (self.root / f"snapshot-{ident}.txt.gz").unlink(missing_ok=True)
        return {"ok": True}

    def configure(self, body):
        self.workload = dict(body)
        self.active = set(range(body["count"]))
        return {"ok": True}

    def keys(self, ids):
        w = self.workload
        if w is None:
            raise ValueError("configure a workload before checking identities")

        def endpoint(address, port):
            return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"

        keys = set()
        for ident in ids:
            proto, sport = ("6" if ident & 1 else "17"), w["base"] + ident // 2
            src, dst = endpoint(w["lan"], sport), endpoint(w["wan"], w["dport"])
            translated = endpoint(w["public"], sport)
            keys.update(((w["lan_if"], proto, src, dst), (w["wan_if"], proto, dst, translated)))
        return keys

    def rows(self, ident):
        if ident not in self.headers:
            raise ValueError("unknown flow snapshot")
        return self.db.execute("SELECT ingress,proto,src,dst,cookie,packets,bytes,mtu,new_src "
                               "FROM flow WHERE shot=? ORDER BY ingress,proto,src,dst", (ident,))

    def check(self, body):
        ident = int(body["snapshot"])
        wanted_ids = (self.active - set(body.get("retire", []))) | set(body.get("admit", []))
        expected = self.keys(wanted_ids)
        actual = set()
        translation = mtu = 0
        w = self.workload
        for row in self.rows(ident):
            actual.add(row[:4])
            translation += row[0] == w["lan_if"] and row[8] != (
                (f"[{w['public']}]:" if ":" in w["public"] else w["public"] + ":")
                + row[2].rsplit(":", 1)[1])
            mtu += "mtu" in body and row[7] != body["mtu"]
        missing, extra = expected - actual, actual - expected
        if not missing and not extra:
            self.active = wanted_ids
        return {"missing_count": len(missing), "unexpected_count": len(extra),
                "missing": sorted(missing)[:16], "unexpected": sorted(extra)[:16],
                "translation_errors": translation, "mtu_errors": mtu,
                "checked": len(actual)}

    def compare(self, body):
        before, after = int(body["before"]), int(body["after"])
        excluded_keys = self.keys(body.get("exclude_ids", [])) if body.get("exclude_ids") else set()
        excluded = set(body.get("excluded_cookies", []))
        if body.get("excluded_from"):
            reference = int(body["excluded_from"])
            if reference not in self.headers:
                raise ValueError("unknown exclusion snapshot")
            excluded.update(row[0] for row in self.db.execute(
                "SELECT cookie FROM flow WHERE shot=? EXCEPT SELECT cookie FROM flow WHERE shot=?",
                (before, reference)))
        survivors = self.keys(range(self.workload.get("survivors", 0))) if self.workload else set()
        counts = dict(missing_count=0, unexpected_count=0, regenerated_count=0,
                      unchanged_errors=0, progress_errors=0, survivor_progress_errors=0)
        evidence = {key: [] for key in ("missing", "unexpected", "regenerated", "survivors_regenerated", "errors")}

        def note(kind, key):
            if len(evidence[kind]) < 65:
                evidence[kind].append(key)

        old, new = iter(self.rows(before)), iter(self.rows(after))
        a, b = next(old, None), next(new, None)
        while a is not None or b is not None:
            if b is None or (a is not None and a[:4] < b[:4]):
                counts["missing_count"] += 1
                if a[4] not in excluded and a[:4] not in excluded_keys and not body.get("allow_missing"):
                    counts["unchanged_errors"] += 1
                note("missing", a[:4])
                a = next(old, None)
                continue
            if a is None or b[:4] < a[:4]:
                counts["unexpected_count"] += 1
                note("unexpected", b[:4])
                b = next(new, None)
                continue
            key = a[:4]
            ignored = a[4] in excluded or key in excluded_keys
            regenerated = a[4] != b[4] or b[5] < a[5]
            if regenerated and not ignored:
                counts["regenerated_count"] += 1
                note("regenerated", key)
                if key in survivors:
                    note("survivors_regenerated", key)
            if not ignored and not (regenerated and body.get("allow_regenerated")):
                if regenerated:
                    counts["unchanged_errors"] += 1
                    note("errors", key)
                if b[5] <= a[5]:
                    counts["progress_errors"] += 1
                    if key in survivors:
                        counts["survivor_progress_errors"] += 1
            a, b = next(old, None), next(new, None)
        return {**counts, **evidence, "checked": self.headers[after]["flow_count"]}

    def reset(self):
        with self.lock:
            self.db.close()
            for ident in self.headers:
                (self.root / f"snapshot-{ident}.txt.gz").unlink(missing_ok=True)


async def observe(operation, body, state):
    if operation in {"state", "summary"}:
        return await asyncio.to_thread(read_state, summary=operation == "summary")
    if operation == "delete_table":
        from .agent import exec_cmd
        started = time.monotonic()
        deleted = await exec_cmd({"argv": ["nft", "delete", "table", "inet", body["table"]],
                                  "timeout_ms": body.get("timeout", 30) * 1000}, state)
        result = await observe("wait_entries", {"count": 0, "unbound": True,
                                                "timeout": body.get("timeout", 30)}, state)
        return {**result, "delete_seconds": time.monotonic() - started, "delete_rc": deleted["rc"]}
    if operation == "wait_entries":
        start = time.monotonic()
        while True:
            result = await asyncio.to_thread(read_state, summary=True)
            if result["entries"] == body["count"] and (not body.get("unbound") or not result["bindings"]):
                return {**result, "wait_seconds": time.monotonic() - start}
            if time.monotonic() - start >= body.get("timeout", 90):
                raise TimeoutError(f"expected {body['count']} entries: {result}")
            await asyncio.sleep(0.1)
    if "snapshots" not in state:
        state["snapshots"] = Snapshots(state["root"])
    store = state["snapshots"]
    if operation == "reset":
        await asyncio.to_thread(store.reset)
        del state["snapshots"]
        (state["root"] / "flows.sqlite").unlink()
        return {"ok": True}
    methods = {"snapshot": store.capture, "release": store.release,
               "workload": store.configure, "check": store.check, "compare": store.compare}
    def run():
        with store.lock:
            return methods[operation](body)
    return await asyncio.to_thread(run)
