"""Common pytest reporting and hardware ownership for every ASK suite."""

import importlib.metadata
import os
import random
import tempfile
import time
from pathlib import Path

import pytest

from ask_orch.artifacts import artifact_dir, record
from ask_orch.lifecycle import bench_lock
from ask_orch.provenance import checkout


def pytest_addoption(parser):
    parser.addoption(
        "--release",
        action="store_true",
        help="require hardware capabilities and reject unexpected skips",
    )
    parser.addoption(
        "--module-order-seed", type=int,
        help="shuffle modules reproducibly while preserving each module's test order",
    )


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config):
    config._ask_broken = None
    if hasattr(config, "workerinput"):
        config._ask_run_dir = Path(config.workerinput["ask_run_dir"])
        os.environ["ASK_TEST_RUN_DIR"] = str(config._ask_run_dir)
        return
    root = Path(
        os.environ.get(
            "ASK_TEST_ARTIFACTS",
            os.environ.get("ASK_FLOWTABLE_ARTIFACTS", f"/tmp/ask-tests-{os.getuid()}"),
        )
    )
    root.mkdir(parents=True, exist_ok=True)
    config._ask_run_dir = Path(
        tempfile.mkdtemp(prefix=time.strftime("%Y%m%d-%H%M%S-"), dir=root)
    )
    os.environ["ASK_TEST_RUN_DIR"] = str(config._ask_run_dir)
    if not config.option.xmlpath:
        config.option.xmlpath = str(config._ask_run_dir / "junit.xml")
    versions = {
        d.metadata["Name"]: d.version for d in importlib.metadata.distributions()
    }
    source = checkout(Path(__file__).resolve().parents[2])
    # Only bench settings: credentials and unrelated environment variables
    # never belong in a distributable test report.
    settings = {
        key: os.environ[key]
        for key in (
            "ASK_TARGET_IP",
            "ASK_TARGET_DEV",
            "ASK_TARGET_LAN_IF",
            "ASK_TARGET_WAN_IF",
            "ASK_LAN_VM",
            "ASK_LAN_NIC",
            "ASK_WAN_IP",
            "ASK_WAN_IPERF_IP",
            "ASK_WAN_INJECT_IF",
            "ASK_KERNEL_SOURCE",
            "ASK_FLOWTABLE_CHURN",
            "ASK_FLOWTABLE_CHURN_SECONDS",
            "ASK_FLOWTABLE_BASELINE",
            "ASK_FLOWTABLE_MIN_GBPS",
            "ASK_IPSEC_IPERF",
            "ASK_IPSEC_IPERF_BPS",
        )
        if os.environ.get(key)
    }
    record(
        "environment",
        {
            "revision": source["revision"],
            "checkout": source,
            "packages": versions,
            "bench": settings,
            "release": config.getoption("--release"),
        },
        nodeid="session",
    )


@pytest.hookimpl(optionalhook=True)
def pytest_configure_node(node):
    node.workerinput["ask_run_dir"] = str(node.config._ask_run_dir)


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_collection_modifyitems(config, items):
    for item in items:
        suite = Path(item.path).parent.name
        item.add_marker("host" if suite == "host_tests" else "hardware")
        if suite == "startup_tests":
            item.add_marker("destructive")
        if item.path.name == "smoke.py":
            item.add_marker("smoke")
        if "pppoe_rig" in item.fixturenames:
            item.add_marker(pytest.mark.requires("pppd"))
        if "smcrouted" in item.fixturenames:
            item.add_marker(pytest.mark.requires("smcrouted"))
        if item.path.name.startswith("profile_") or item.path.name in {
            "flowtable_churn.py",
            "ipsec_vlan_iperf_probe.py",
            "reassembly_storm.py",
            "ipv6_reassembly_storm.py",
        }:
            item.add_marker("slow")
        if (
            (item.path.name == "flowtable_offload.py"
             and getattr(item, "originalname", None) == "test_terminal")
            or item.path.name == "flowtable_unregister.py"
        ):
            item.add_marker("destructive")
        if item.path.name == "flowtable_churn.py":
            # Churn requires both a minimum soak and a complete tuple rotation.
            # UART round trips can make the latter longer than the soak. Leave
            # an hour for that coverage, including setup, drain and leak scans.
            item.add_marker(
                pytest.mark.timeout(
                    max(3600, int(os.environ.get("ASK_FLOWTABLE_CHURN_SECONDS", "900")) + 420),
                    func_only=True,
                )
            )
    # pytest applies -k/-m inside this hook. Mark first; validate only the
    # remaining selection so `-m host -n auto` never reserves the bench.
    result = yield
    seed = config.getoption("--module-order-seed")
    if seed is not None:
        modules = {}
        for item in items:
            modules.setdefault(item.path, []).append(item)
        groups = list(modules.values())
        random.Random(seed).shuffle(groups)
        items[:] = [item for group in groups for item in group]
    record("selection", {"module_order_seed": seed,
                         "nodeids": [item.nodeid for item in items]}, nodeid="session")
    if any(item.get_closest_marker("hardware") for item in items):
        if getattr(config.option, "numprocesses", None) or hasattr(
            config, "workerinput"
        ):
            raise pytest.UsageError(
                "hardware tests require one runner; use test-host for parallel host tests"
            )
    return result


@pytest.fixture(scope="session", autouse=True)
def hardware_bench(request):
    if not any(item.get_closest_marker("hardware") for item in request.session.items):
        yield
        return
    required = {"ASK_TARGET_DEV"}
    if any(Path(item.path).parent.name == "tests" for item in request.session.items):
        required.update(
            {"ASK_WAN_IPERF_IP", "ASK_LAN_VM", "ASK_LAN_NIC"}
        )
    if any(
        item.get_closest_marker("hardware")
        and any(
            group in item.path.name
            for group in ("mcast", "mroute", "multicast", "profile")
        )
        for item in request.session.items
    ):
        required.add("ASK_WAN_INJECT_IF")
    missing = sorted(key for key in required if not os.environ.get(key))
    if missing:
        pytest.fail(
            "missing bench settings: "
            + ", ".join(missing)
            + "; configure .ask-test.mk from .ask-test.mk.example or export ASK_* variables"
        )
    resources = ["serial:" + os.path.realpath(os.environ["ASK_TARGET_DEV"])]
    resources.extend(
        prefix + os.environ[key]
        for key, prefix in (
            ("ASK_TARGET_IP", "dut:"),
            ("ASK_LAN_VM", "lan:"),
            ("ASK_WAN_IPERF_IP", "wan:"),
        )
        if os.environ.get(key)
    )
    with bench_lock(resources):
        yield


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item):
    if item.get_closest_marker("hardware"):
        if item.config._ask_broken:
            pytest.skip("bench requires recovery: " + item.config._ask_broken)


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item, call):
    report = yield
    if (
        report.skipped
        and item.config.getoption("--release")
        and not item.config._ask_broken
        and not getattr(report, "wasxfail", None)
    ):
        report.outcome = "failed"
        report.longrepr = (
            f"release run cannot skip required coverage: {report.longrepr}"
        )
    item._ask_failed = getattr(item, "_ask_failed", False) or report.failed
    if (
        report.failed
        and report.when in {"setup", "teardown"}
        and item.get_closest_marker("hardware")
    ):
        item.config._ask_broken = item.nodeid
    path = artifact_dir(item.nodeid)
    report.user_properties.append(("artifacts", str(path)))
    record(
        report.when,
        {
            "nodeid": item.nodeid,
            "phase": report.when,
            "outcome": report.outcome,
            "duration_s": report.duration,
            "failure": str(report.longrepr) if report.longrepr else None,
            "sections": report.sections,
        },
        nodeid=item.nodeid,
    )
    return report


def pytest_terminal_summary(terminalreporter):
    terminalreporter.write_line(f"Artifacts: {terminalreporter.config._ask_run_dir}")
