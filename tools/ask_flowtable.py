#!/usr/bin/env python3
"""Apply owned Linux flowtable policy after proving old hardware has drained."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

TABLE = "ask_flowtable"
MARKER = "ask-flowtable/v1:"
CONFIG = Path("/etc/ask/flowtable.json")
PROC = Path("/proc/cdx_flowtable")
LOCK = Path("/run/lock/ask-flowtable.lock")
DRAIN_FIELDS = ("bindings", "entries", "handle_refs", "neighbour_refs", "quarantine")
ADDRESS_FIELDS = {
    "source": "original ip saddr", "destination": "original ip daddr",
    "reply_source": "reply ip saddr", "reply_destination": "reply ip daddr",
}
PORT_FIELDS = {
    "source_port": "original proto-src", "destination_port": "original proto-dst",
    "reply_source_port": "reply proto-src", "reply_destination_port": "reply proto-dst",
}


class PolicyError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise PolicyError(message)


def integer(value, minimum, maximum, label):
    require(type(value) is int and minimum <= value <= maximum, f"{label}: expected integer {minimum}..{maximum}")
    return value


def port(value):
    if type(value) is int:
        return str(integer(value, 1, 65535, "port"))
    require(isinstance(value, dict) and set(value) == {"min", "max"}, "port: expected integer or {min, max}")
    low, high = (integer(value[k], 1, 65535, "port " + k) for k in ("min", "max"))
    require(low <= high, "port: min exceeds max")
    return f"{low}-{high}"


def match(rule, *, exclusion=False):
    allowed = set(ADDRESS_FIELDS) | set(PORT_FIELDS) | {"name", "protocol", "port", "mark"}
    require(isinstance(rule, dict) and not set(rule) - allowed, "match: unknown fields or non-object")
    require(not exclusion or set(rule) - {"name"}, "exclusion: at least one selector is required")
    if "name" in rule:
        require(isinstance(rule["name"], str) and 0 < len(rule["name"]) <= 64, "match name: expected 1..64 characters")
    parts = []
    if "protocol" in rule:
        require(rule["protocol"] in ("tcp", "udp"), "protocol: only tcp and udp are supported")
        parts.append("meta l4proto " + rule["protocol"])
    for field, expression in ADDRESS_FIELDS.items():
        if field in rule:
            require(isinstance(rule[field], str), field + ": expected IPv4 address or prefix")
            try:
                address = ipaddress.IPv4Network(rule[field], strict=True)
            except ValueError as error:
                raise PolicyError(field + ": " + str(error)) from error
            parts.append(f"ct {expression} {address}")
    for field, expression in PORT_FIELDS.items():
        if field in rule:
            parts.append(f"ct {expression} {port(rule[field])}")
    if "mark" in rule:
        mark = rule["mark"]
        require(isinstance(mark, dict) and set(mark) == {"value", "mask"}, "mark: expected {value, mask}")
        value, mask = (integer(mark[k], 0, 0xffffffff, "mark " + k) for k in ("value", "mask"))
        require(mask != 0 and value & ~mask == 0, "mark: nonzero mask must contain every value bit")
        parts.append(f"ct mark & {mask:#x} == {value:#x}")
    if "port" in rule:
        value = port(rule["port"])
        return [" ".join(parts + [f"ct {expression} {value}"]) for expression in PORT_FIELDS.values()]
    return [" ".join(parts)]


def validate(policy):
    require(isinstance(policy, dict) and set(policy) == {"version", "enabled", "devices", "scope", "exclude"},
            "configuration requires exactly version, enabled, devices, scope and exclude")
    require(type(policy["version"]) is int and policy["version"] == 1, "unsupported configuration version")
    require(type(policy["enabled"]) is bool, "enabled: expected boolean")
    devices = policy["devices"]
    require(isinstance(devices, list) and len(devices) == 2 and
            all(isinstance(d, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", d) for d in devices) and
            devices[0] != devices[1], "devices: expected two distinct interface names")
    for field in ("scope", "exclude"):
        require(isinstance(policy[field], list) and len(policy[field]) <= 256, field + ": expected at most 256 matches")
        for rule in policy[field]:
            match(rule, exclusion=field == "exclude")
    require(not policy["enabled"] or policy["scope"], "enabled policy requires an explicit admission scope")
    return policy


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def load_policy(path):
    with Path(path).open("rb") as stream:
        data = stream.read(65537)
    require(len(data) <= 65536, "configuration exceeds 64 KiB")
    try:
        return validate(json.loads(data, object_pairs_hook=unique_object))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise PolicyError("invalid JSON: " + str(error)) from error


def policy_hash(policy):
    return hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def render(policy):
    validate(policy)
    require(policy["enabled"], "disabled policy has no nftables table to render")
    devices = ", ".join(json.dumps(d) for d in policy["devices"])
    lines = [f"table inet {TABLE} {{", f' comment "{MARKER}{policy_hash(policy)}"',
             f" flowtable fast {{ hook ingress priority 0; devices = {{ {devices} }}; flags offload; }}",
             " chain admit {", "  type filter hook forward priority 10; policy accept;",
             "  meta nfproto != ipv4 return", "  meta l4proto != { tcp, udp } return",
             "  ct direction != original return", "  ct state != established return",
             "  ct mark != 0 return", "  ct status snat return", "  ct status dnat return"]
    for field, action in (("exclude", "return"), ("scope", "flow add @fast")):
        for rule in policy[field]:
            for expression in match(rule, exclusion=field == "exclude"):
                lines.append("  " + " ".join(part for part in (expression, action) if part))
    return "\n".join(lines + [" }", "}", ""])


def backend_state():
    try:
        text = PROC.read_text()
    except FileNotFoundError:
        require(not Path("/sys/module/ask_flowtable").exists(), "adapter teardown is still in progress")
        return None
    state = {}
    for line in text.splitlines():
        key, value = line.split(" ", 1)
        if key != "flow":
            state[key] = value if key == "owner" else int(value)
    require(all(k in state for k in DRAIN_FIELDS + ("fatal", "observe", "owner", "invalidated")), "incomplete backend diagnostics")
    return state


@contextmanager
def policy_lock(timeout=30):
    LOCK.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                require(time.monotonic() < deadline, "another policy operation still holds the lock")
                time.sleep(0.05)
        yield fd
    finally:
        os.close(fd)


class Runtime:
    lock_fd = None

    @contextmanager
    def locked(self):
        with policy_lock() as fd:
            self.lock_fd = fd
            try:
                yield
            finally:
                self.lock_fd = None

    def nft(self, *arguments, script=None):
        # A surviving nft child must keep the same lease if its controller
        # is killed. Otherwise an older transaction could commit after a
        # newer controller acquired the lock and installed its policy.
        result = subprocess.run(["nft", *arguments], input=script, text=True, capture_output=True,
                                timeout=15, env={**os.environ, "LC_ALL": "C"},
                                pass_fds=() if self.lock_fd is None else (self.lock_fd,))
        require(result.returncode == 0, "nft: " + (result.stderr or result.stdout).strip())
        return result.stdout

    def table(self):
        tables = json.loads(self.nft("-j", "list", "tables"))["nftables"]
        if not any(t.get("table", {}).get("name") == TABLE and t["table"]["family"] == "inet" for t in tables):
            return None
        contents = json.loads(self.nft("-j", "list", "table", "inet", TABLE))["nftables"]
        table = next(t["table"] for t in contents if "table" in t)
        comment = table.get("comment", "")
        require(re.fullmatch(re.escape(MARKER) + r"[0-9a-f]{64}", comment),
                "refusing to modify a table without this controller's ownership marker")
        return {"hash": comment[len(MARKER):], "contents": contents}

    def state(self):
        return backend_state()

    def require_device(self, name):
        require(Path("/sys/class/net", name).exists(), "interface does not exist: " + name)

    def drain(self, timeout=15):
        deadline = time.monotonic() + timeout
        while True:
            state = self.state()
            if state is None:
                return None
            require(not state["fatal"], "hardware retirement failed; full provider teardown and fresh boot required")
            if all(state[k] == 0 for k in DRAIN_FIELDS):
                return state
            require(time.monotonic() < deadline, "old hardware or bindings have not drained; no replacement policy installed")
            time.sleep(0.05)

    def remove(self):
        if self.table():
            self.nft("delete", "table", "inet", TABLE)
        return self.drain()

    def apply(self, policy):
        validate(policy)
        script = render(policy) if policy["enabled"] else None
        with self.locked():
            owned, state = self.table(), self.state()
            require(owned or not state or not state["bindings"], "another flowtable owns the backend bindings")
            if policy["enabled"]:
                require(state and state["owner"] == "flowtable" and not state["observe"], "an active flowtable provider is required")
                require(not state["fatal"], "hardware retirement failed; fresh boot required")
                for device in policy["devices"]:
                    self.require_device(device)
            drained = self.remove()
            if not script:
                return {"enabled": False, "drained": drained}
            try:
                # nft --check can invoke backend binding callbacks. Run it
                # only after the previous table and hardware have drained.
                self.nft("--check", "-f", "-", script=script)
                self.drain()
                self.nft("-f", "-", script=script)
                current, state = self.table(), self.state()
                require(current and current["hash"] == policy_hash(policy) and state and
                        state["bindings"] == len(policy["devices"]) and not state["fatal"] and not state["invalidated"],
                        "new policy did not acquire healthy backend bindings")
            except (PolicyError, OSError, subprocess.SubprocessError, ValueError) as error:
                try:
                    self.remove()
                except (PolicyError, OSError, subprocess.SubprocessError, ValueError) as cleanup:
                    raise PolicyError(f"apply failed: {error}; cleanup requires attention: {cleanup}") from error
                raise PolicyError(f"apply failed; acceleration disabled: {error}") from error
            return {"enabled": True, "policy_hash": current["hash"], "drained": drained, "backend": state}

    def stop(self):
        with self.locked():
            owned, state = self.table(), self.state()
            require(owned or not state or not state["bindings"], "another flowtable owns the backend bindings")
            return {"enabled": False, "drained": self.remove()}

    def status(self):
        with self.locked():
            current, state = self.table(), self.state()
            return {"policy_installed": bool(current), "policy_hash": current["hash"] if current else None,
                    "admission_ready": bool(current and state and state["bindings"] == 2 and
                                            not state["fatal"] and not state["invalidated"] and not state["observe"]),
                    "backend": state}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "render", "apply", "stop", "status"))
    parser.add_argument("--config", type=Path, default=CONFIG)
    args = parser.parse_args(argv)
    try:
        runtime = Runtime()
        if args.command in ("check", "render", "apply"):
            policy = load_policy(args.config)
            if args.command == "render":
                print(render(policy), end="")
                return 0
            result = ({"valid": True, "policy_hash": policy_hash(policy)} if args.command == "check"
                      else runtime.apply(policy))
        else:
            result = getattr(runtime, args.command)()
        print(json.dumps(result, sort_keys=True))
        return 0
    except (PolicyError, OSError, subprocess.SubprocessError, ValueError) as error:
        print("ask-flowtable: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
