# ASK Test Bench Setup

This document describes how to set up the ASK end-to-end test bench from
scratch. It covers the physical/logical topology, what each machine needs,
how to reach the console of each node, and how to run the suite.

Bench addresses, VM names and client interfaces are local configuration.
Copy `.ask-test.mk.example` to `.ask-test.mk` and fill in your values;
Git ignores `.ask-test.mk`. Hardware runs report missing settings before
opening a console or changing the bench. Host tests need no bench settings.

---

## Topology
The bench is three roles. The orchestrator hosts a libvirt LAN VM and connects to the physical DUT.

```
        ┌─────────────────────┐         WAN segment
        │  Orchestrator /     │◄────────────────────────────┐
        │  WAN host           │   (DUT's WAN-facing net)    │
        │                     │                             │
        │  · builds the image │                      ┌──────┴───────┐
        │  · runs pytest      │      DUT WAN port    │     DUT      │
        │  · iperf3 server    ├─────────────────────►│ (gateway     │
        │  · TFTP server      │                      │   under test)│
        │  · WAN test agent   │                      └──────┬───────┘
        └─────────┬───────────┘                      DUT LAN port
                  │ USB-serial to DUT console (UART)         │
                  │ USB-C to DUT data port (agent, optional) │
                  │ virtio/QGA to client                     │ DHCP-served
                  │                                          │ LAN segment
        ┌─────────┴───────────┐                              │
        │  LAN client         │◄─────────────────────────────┘
        │  · DHCP client      │
        │  · iperf3 / tcpdump │      (behind the DUT's NAT)
        └─────────────────────┘
```

Roles:

- **Orchestrator / WAN host** — builds the firmware image, serves it over
  TFTP, runs the pytest suite, hosts the WAN-side iperf3 server, and runs a
  WAN-side test agent. It sits on the DUT's **WAN** network. It also holds
  the DUT serial link and the client VM's virtio channel. In our lab this is a
  single Linux workstation.

- **DUT** — the LS1046A-class gateway under test. It runs the ASK test
  image (TFTP-booted). It has (at least) a **WAN-facing** port on the
  orchestrator/WAN segment and a **LAN-facing** port to the client. It runs
  a DHCP server + NAT on the LAN side, exactly like the shipping product.

- **LAN client** — a machine or VM cabled to the DUT's LAN port. It is a
  plain **DHCP client**: it takes its address from the DUT and lives behind
  the DUT's NAT. The traffic tests originate/sink here. In our lab this is a
  libvirt VM on the orchestrator host.

DUT control uses a serial line: the UART, or the DUT's USB serial port when one
is cabled (see [DUT agent over USB](#dut-agent-over-usb)). LAN control uses the
VM's QEMU guest agent. All stay available when a test interrupts forwarding,
NAT, XFRM policy or a network link.

---

## What each node needs

### Runner dependencies and installation

Use a Linux orchestrator with Python 3.13. The pinned environment was captured
on Python 3.13.5; the harness uses Linux process locks, network namespaces and
signal-based timeouts. Make runs `/opt/askd-agent/venv/bin/python`, so use that
interpreter when inspecting or installing its packages.

[`tools/requirements.txt`](../tools/requirements.txt) is the source of truth for
all runner and WAN-agent Python package versions, including indirect dependencies.

| Python package | Purpose |
|---|---|
| `pytest` | Discovery, fixtures, assertions, selection, terminal output and JUnit |
| `pytest-asyncio` | Async tests and fixture event loops |
| `pytest-timeout` | Test-body watchdog; required even for short selections |
| `pytest-xdist` | Optional parallel execution of host tests; installed with the runner |
| `aiohttp` | WAN HTTP agent and client |
| `pyserial` | DUT UART and manual console access |
| `scapy`, `pyroute2`, `cffi` | Packet and network tooling in the harness environment |
| `PyYAML` | Kernel-log allowlist loading |

On Debian 13, install the host prerequisites, then the pinned environment:

```sh
sudo apt-get update
sudo apt-get install -y python3 python3-venv make git sudo build-essential
make test-env
/opt/askd-agent/venv/bin/python -m pip check
```

`make test-env` creates or updates the virtualenv and installs the complete
requirements file. It does not start tests or deploy an agent. The WAN service
shares this environment, so update dependencies between bench runs.
`make deploy-agent-wan` also installs the same requirements while deploying
the WAN service. `make setup` prepares the Yocto build host; runner dependency
installation is the separate `make test-env` step.

Additional system dependencies depend on the selected suite:

| Selection | Additional requirements |
|---|---|
| Python harness checks in `tools/host_tests/harness.py` | Runner environment only; no board or compiler |
| Compiled host regressions | C/C++ compiler, headers, standard C++ library, AddressSanitizer and UndefinedBehaviorSanitizer; Debian's `build-essential` toolchain supplies these. `HOSTCC` selects a compiler instead of `cc`. |
| SDK/FMC/FMLIB host regressions | Patched kernel and pinned vendor source trees from the image build. `ASK_KERNEL_SOURCE` overrides the kernel tree; it must contain the ASK patches and SDK headers. |
| DUT traffic tests | WAN agent, `ip`/`bridge`/`tc`, `iptables`, `conntrack`, `ethtool`, `iperf3`, `tcpdump`, and access to the DUT UART and LAN guest agent |
| PPPoE tests and ISP profile | WAN-side `pppd` and `/usr/sbin/pppoe-server`, kernel PPPoE support, and the corresponding tools/modules in the DUT image |
| Image building and booting | `make setup` build dependencies, kas, a TFTP server and the staged image/DTB |

For a Debian WAN host running hardware tests, the system tools can be installed
with:

```sh
sudo apt-get install -y rsync iproute2 iptables nftables conntrack ethtool \
    iperf3 tcpdump ppp pppoe coreutils procps psmisc libvirt-clients
```

The WAN deployment target also requires systemd. An existing libvirt installation
must manage the configured LAN VM; `libvirt-clients` supplies `virsh` but does
not create that VM. Full host regression runs need the fetched vendor sources
even though they do not need physical hardware. Build the ASK image once to
populate those source trees; the tests name missing sources in their errors.

When changing dependencies, update the pins together in a fresh Python 3.13
environment, run `pip check`, and validate the affected test selections before
deploying the updated environment. `pytest-asyncio` and `pytest-timeout` are
also version-checked in [`tools/pyproject.toml`](../tools/pyproject.toml); update
those entries when changing their pins. Every run records installed package
versions in its session artifacts.

If pytest reports `Missing required plugins`, rerun `make test-env`. Installing
pytest into the system interpreter does not update the virtualenv Make uses.

### Orchestrator / WAN host

Packages / services:

- **Build toolchain for the image** — `kas` and the OpenEmbedded/BitBake
  host dependencies (see `make setup`, which installs them). The image is
  built with `kas build`, never a bare `bitbake`.
- **A TFTP server** exporting the staged image directory, reachable from
  the DUT's U-Boot. `make stage-image` copies the built image into the TFTP
  root under the name U-Boot fetches.
- **`iperf3`** — run as a server here (see [iperf3 server](#the-iperf3-server)).
- **`libvirt` + `libvirt-clients`** — only if the client is a VM on this
  host. `virsh` reaches the client's QEMU guest agent.
- **`python3` + `venv`** — for the WAN-side test agent and the pytest
  virtualenv (`make deploy-agent-wan` bootstraps the venv and installs the
  agent's requirements).
- **A USB-to-serial adapter** to the DUT's console header, plus permission
  to read it (the `dialout`/`plugdev` group, or run under `sudo`).
- **Optionally, a USB-C cable** from the DUT's USB-C data port (not its power
  input) to a USB port here, for the faster agent channel; the kernel's
  `cdc_acm` driver presents it as a `/dev/ttyACM*` node.
- Membership in the `libvirt`/`kvm` groups if the client is a local VM.

Test agent: `make deploy-agents` installs the WAN-side agent as a systemd
service and brings it up. Verify with a health check against the agent port
on loopback.

### DUT

Nothing to install — the ASK test image carries everything (the on-DUT test
kernel recorder auto-starts at boot). You only need to:

- Wire its WAN port to the orchestrator/WAN segment and its LAN port to the
  client.
- Wire its serial console to the orchestrator's USB-serial adapter.
- Point its U-Boot `ask` boot flow at the orchestrator's TFTP server (see
  [Booting the image](#booting-the-image)).

The DUT uses Yocto's packaged Python dependencies. Its package lists live in
[`ask-image.bb`](../meta-ask/recipes-core/images/ask-image.bb) and the
[`ask-test-agent` recipe](../meta-ask/recipes-support/ask-test-agent/ask-test-agent_1.0.bb).
The host requirements file is installed on the orchestrator/WAN host only.
The image supplies routing/firewall tools, `smcrouted`/`smcroutectl`, PPP/PPPoE,
packet capture, traffic generators, ASK modules and the test agent.

Use an agent built from the same checkout as the runner. Kernel capture requires
`capture_protocol: 2` and the checkout's `serial_protocol`
(`askd_agent.wire.VERSION`) in the agent's health response, readable
`/dev/kmsg`, and retained boot logs.
After agent changes, rebuild, stage and boot the updated image. Preflight rejects
an older agent; installing host packages cannot upgrade the agent inside the
DUT's initramfs. Release runs also require the tools named by selected tests.

### LAN client

A libvirt VM on the DUT's LAN port, configured as a **DHCP client** so it
picks up its address, gateway, and DNS from the DUT. The test image is the sole
DHCP server on its LAN/AP subnets; authoritative mode lets clients renew after
an initramfs reboot loses the server's lease database. Install:

- A **DHCP client** (whatever your distro ships — `dhcpcd`, `udhcpc`,
  `dhclient`, `systemd-networkd`, or `NetworkManager`), bringing up the
  LAN-facing NIC automatically at boot.
- **`iperf3`** — the LAN endpoint for throughput tests (it runs both as a
  client toward the WAN server and, for some tests, as a server).
- **`tcpdump`** — the LAN-side capture tool the tests grep for expected
  frames.
- **`iproute2`** (`ip`) — interface/route/neighbor manipulation.
- **`python3`** — the harness runs compressed snippets through the QEMU guest
  agent (see `lan_run_python`). Namespace cases
  need Python 3.12 or newer for `os.setns`; Python 3.13 matches the runner.
- **Scapy for the LAN's system `python3`** — used by the staged ARP and packet
  helpers. Installing it in the orchestrator's virtualenv does not install it
  on the LAN client.
- **`ethtool`, `coreutils`, `procps`, `psmisc`** — link statistics, script
  staging, timeouts and process cleanup.

For a Debian 13 LAN VM with its DHCP client already configured:

```sh
sudo apt-get install -y python3 python3-scapy iproute2 iputils-ping iperf3 \
    tcpdump ethtool coreutils procps psmisc qemu-guest-agent
```

Expose a virtio channel named `org.qemu.guest_agent.0` in the libvirt domain
and enable `qemu-guest-agent` inside the VM. It runs as root for namespaces,
interface changes and raw sockets. `guest-exec` and `guest-exec-status` must be
enabled. The harness checks them before LAN setup. Loki already provides this
channel; no 9p mount or shared checkout is needed.

[QEMU documents the command execution protocol](https://www.qemu.org/docs/master/interop/qemu-ga-ref.html#command-guest-exec).
The harness sends source through `input-data`, checks output truncation, and
uses a guest-side `timeout` so commands remain bounded if the runner stops.

---

## Console / serial access

The DUT uses its serial console for bootstrap, then a framed agent session on
the same UART, or on its USB serial port when `ASK_TARGET_AGENT_DEV` names one.
The LAN VM uses its separate virtio guest-agent channel.

### DUT console

- USB-to-serial adapter to the DUT's console header.
- **115200 baud, 8N1.**
- Appears on the orchestrator as a character device (e.g. a `/dev/ttyUSB*`
  node). Reading it needs the `dialout`/`plugdev` group or `sudo`.
- Interactively: `tio <device>` (or any serial terminal).
- The harness opens it via `Console.target()`.

### Client console

The VM's serial console remains available for manual recovery:
`tio $(sudo virsh ttyconsole <domain>)`. Normal tests use QGA through libvirt.

**One reader per physical UART.** Detach manual terminals before running DUT
tests. One session owns the UART; `Console.target()` handles used by individual
tests borrow that session instead of opening another reader.

### DUT agent over USB

The test image presents a USB CDC-ACM serial port on the DUT's USB-C data port.
The HD3SS3220 detects an attached host, the controller switches to the device
role (thumb drives still mount when a device is attached instead), and
`/etc/init.d/usb-agent` binds the gadget. init keeps a root login on its
`ttyGS0` (`login -f root`, no getty: a USB serial port hangs up whenever its host
closes it). On the orchestrator it appears as
`/dev/serial/by-id/usb-Mono_ASK_test_agent_<eth4 MAC>-if00`.

Set `ASK_TARGET_AGENT_DEV` to that path and the session's agent runs there: the
same protocol, without the UART's 115200-baud line rate or its paced writes. The
UART stays the console for U-Boot, the boot log, reboot and recovery, and stays
required. Rig tests run roughly twice as fast; a plain rig fixture's setup and
teardown drop from about 18 s to 3 s.

If the node is missing, check the DUT side over the UART:
`cat /sys/class/typec/port0/data_role` should read `[device]`, and
`/sys/kernel/debug/usb/2f00000.usb/mode` `device`.

---

## The iperf3 server

Throughput and data-plane tests drive traffic between the client (LAN) and
an **iperf3 server that lives on the DUT's WAN network** — i.e. somewhere
the DUT can reach out of its WAN port. In our lab the orchestrator host is
itself on that segment, so we just run the server there:

```sh
iperf3 -s -D        # daemonized server on the WAN host
```

It can equally be a separate box on the WAN segment. What matters is that
the DUT's WAN side can route to it. Tell the harness where it is with
`ASK_WAN_IPERF_IP` (see below). The tunnel/forwarding tests also use the
WAN host's own address as an endpoint, so keep the WAN host reachable from
the DUT throughout the run.

---

## Building the image

From the repo root on the orchestrator:

```sh
make setup          # one-time: install host build dependencies
make ask-image      # kas build of the ASK test image
make stage-image    # copy the built image into the TFTP root
```

`make ask-image` is a thin wrapper around `kas build` against the meta-ask
manifest; `make stage-image` places the image where U-Boot fetches it.

Always prefer KASAN for testing and debugging. `make ask-image` always enables
KASAN memory-error instrumentation. The DUT
suite refuses to run on a kernel without `CONFIG_KASAN=y`. Direct kas builds
must also set `KASAN=1`.

## Booting the image

The DUT TFTP-boots the staged image from U-Boot — it is **not** flashed. At
the DUT's U-Boot prompt (interrupt autoboot over the serial console), run
the board's `ask` boot flow, which TFTPs the image from the orchestrator and
boots it in RAM. Point U-Boot's environment at your TFTP server's address
and the staged image name.

The root filesystem is an initramfs, so **every boot is clean** — on-DUT
changes do not persist across a reboot. The boot service retains the kernel
log locally. Pytest starts the UART agent after logging into the root console.

---

## Configuring the harness

Put the bench IPs, VM name and client NIC in the ignored `.ask-test.mk` so
plain `make test` reuses them. Environment variables and make command-line
assignments can override that file. `ASK_*` variables pass through sudo
without shell interpolation, including values with spaces.

| Variable | What it points at | Setting |
|---|---|---|
| `DUT_IP` / `ASK_TARGET_IP` | DUT address used by traffic tests | Optional; tests usually discover interface addresses |
| `ASK_TARGET_DEV` | DUT serial device | Required |
| `ASK_TARGET_AGENT_DEV` | DUT's USB serial port (`ttyGS0` on its USB-C data port), e.g. `/dev/serial/by-id/usb-Mono_ASK_test_agent_<eth4 MAC>-if00` | Optional; carries the agent instead of the UART, without its line rate |
| `ASK_TARGET_LAN_IF` | DUT netdev facing the client | Board default: `eth3` |
| `ASK_TARGET_WAN_IF` | DUT netdev facing the WAN | Board default: `eth4` |
| `ASK_LAN_VM` | libvirt domain of the client | Required |
| `ASK_LAN_NIC` | client's LAN-facing NIC name | Required |
| `ASK_WAN_INJECT_IF` | WAN interface for packet injection | Required for multicast and profiles |
| `WAN_AGENT_IP` / `ASK_WAN_IP` | WAN-side test-agent host (HTTP) | `WAN_IP`, or loopback for direct pytest |
| `WAN_IP` / `ASK_WAN_IPERF_IP` | Traffic endpoint on the WAN network | Required |

## Running the suite

Test files use plain names such as `tools/tests/flowtable_bridge.py` and
`tools/host_tests/harness.py`. Helpers and staged peer scripts start with `_`;
pytest discovers the other Python files. Test functions keep the `test_` prefix.

### Interpreting packet counters

ASK adds FMAN interface statistics to `dev_get_stats()`. Consequently,
`ip -s link`, `ifconfig`, `/proc/net/dev`, and sysfs netdev statistics include
both software and hardware traffic, on physical ports and on VLAN devices (see
the [interface counters guide](flowtable/statistics.md) for the units). Use those
totals for volume and header length accounting, not to decide which path
forwarded a packet.

The SDK DPAA driver's `ethtool -S <physical-ingress-port>` counter
`rx packets [TOTAL]` contains software RX only. The harness reads this
counter explicitly and fails if it is absent. Tunnel tests require successful
delivery alongside a small software RX delta; decap tests also require tunnel
RX totals to advance, covering hardware statistics encoding. Edge-case
goldens pin software RX visibility: a low count alone does not distinguish
forwarding from an early drop. Queue occupancy, CPU idle time, conntrack
presence and encapsulation overhead alone do not prove offload.

### Suite invocation

Prerequisites: the DUT is on the test image with its agent responding, the
WAN agent is deployed, the WAN iperf3 server is up, and no manual session is
holding the DUT serial console. The image boots only the flowtable offload
path, so one boot runs the whole suite, `test_flowtable_*` included.

```sh
# one-time runner setup (the dependency snapshot uses Python 3.13)
make test-env
test -e .ask-test.mk || cp .ask-test.mk.example .ask-test.mk
# Edit .ask-test.mk: DUT_IP, WAN_IP, ASK_TARGET_DEV, ASK_LAN_VM, ASK_LAN_NIC.

# ordinary host + DUT suites; ask-test remains an alias
make test

# -k is pytest's name expression, passed as one argument
make test DUT_IP=<dut-address> WAN_IP=<wan-address> K='ipsec or mcast'
make test-dut K=qos ARGS='-m "not slow"'
make test-host K=qos
make test-host ARGS='-n auto'
```

Service recovery loops repeat each ordinary transition twice to catch stale state on
the second recovery. They retain baseline, per-recovery and new-connection
hardware proofs. Multicast stop tests use eight complementary combinations:
each stop method runs with both IP families and both routed and bridged
forwarding across the two modules. Host tests cover the detailed stop logic.

Capacity churn remains an explicit soak, enabled with `ASK_FLOWTABLE_CHURN=1`.
Keep its default 900-second minimum and full tuple turnover for soak runs;
`ASK_FLOWTABLE_CHURN_SECONDS=90` selects a shorter development check. Ordinary
regression runs leave the soak disabled. See [capacity coverage](flowtable/capacity.md).

`DUT_IP` sets `ASK_TARGET_IP`. `WAN_IP` sets both `ASK_WAN_IPERF_IP`
(traffic endpoint) and `ASK_WAN_IP` (agent HTTP endpoint). Use
`WAN_AGENT_IP=127.0.0.1` when the WAN agent is reached locally while traffic
uses another address. Existing `ASK_*` settings and `ASK_TEST_ARGS` still work;
the short aliases take precedence. `ARGS` adds ordinary pytest options.
Make exports the settings through sudo as literal arguments. Direct pytest
invocations need exported `ASK_*` variables; they do not read `.ask-test.mk`.

The runner and WAN agent use `tools/requirements.txt`, pinned to specific
versions. Update it deliberately. The kernel-capture protocol requires the
current DUT agent: rebuild and boot the test image after updating it. An older
agent fails preflight with an upgrade message. `make test-env` updates only
the runner environment; it does not deploy or run tests.

### Results and artifacts

Every selected test uses pytest's standard `PASSED`, `FAILED`, `ERROR`, or
`SKIPPED` status, followed by final totals. Each status line ends in the
test's time across its phases and its place in the run, `PASSED 41.2s [ 27/514]`,
coloured green while every test so far has passed (pass `--color=yes` when
writing to a file). Successful-test stdout stays
captured; failures include their diagnostics. `ARGS=-s` explicitly enables
live output for debugging.

Each invocation creates a unique directory under `/tmp/ask-tests-<uid>` (override
with `ASK_TEST_ARTIFACTS`; `ASK_FLOWTABLE_ARTIFACTS` remains supported).
The final output prints its path. Before creating it, the harness deletes
earlier run directories there older than `ASK_TEST_ARTIFACT_DAYS` (default 3),
and the oldest ones while less than 4 GiB is free; the newest ten always stay.
`/tmp` is a tmpfs on the bench, and a run that fills it fails every later
write, the harness's own included. It contains `junit.xml`, session metadata
(revision, checkout fingerprint, dependency versions, configured endpoints), DUT kernel/boot details,
boot logs, and one directory per test with setup/call/teardown results and
diagnostic artifacts. Test names include a hash so parameterized cases cannot
overwrite each other. Shared module captures and the DUT UART transcript
cover their corresponding fixture lifetimes. `ARGS='--junitxml=path.xml'`
chooses another JUnit destination. Parallel host workers share the run directory.

The checkout fingerprint covers tracked and untracked source files, deletions,
symlinks and executable bits, while respecting Git's ignores. Firmware metadata
records installed agent source hashes, kernel and module build-note hashes, and
the paths and hashes of required tools. Release preflight rejects a DUT agent
that differs from the checkout and checks each selected test's required tools.

### Lifecycle and suite groups

- Shared code lives in `ask_orch` and `_*.py` support modules. Register shared
  fixtures in `conftest.py`; tests request fixtures by parameter name. Reuse
  scenarios through support functions, preserving each test's own identity.
- Test filenames omit `test_`; test functions keep pytest's native `test_`
  prefix and omit repeated module context. For example,
  `flowtable_service_multicast_bridge.py::test_stops_with_acceleration[6-disabled]`.
- Register restoration immediately after acquiring a resource, before the
  next mutation. `CleanupStack` runs every undo in reverse order with a
  separate 45-second budget per callback and reports all failures. Commands
  must check return codes or verify an explicit cleanup postcondition.
- A hardware setup or teardown failure blocks later hardware cases in that
  invocation. Recover the bench before starting a new run. Every command
  reports all failures, so a full run is a complete ledger to fix from;
  `ARGS=-x` stops at the first instead.
- Local process locks cover the DUT, serial device, LAN VM and WAN endpoint.
  Overlapping invocations fail before setup; hardware xdist workers are
  rejected. Locks cover runners on one orchestrator. A shared lab coordinator
  is needed if several orchestrators can access the same physical bench.
- Kernel capture is automatic around each DUT test and its function fixtures.
  The two module-scoped profiles also capture setup and teardown. Missing
  logs, ring overruns and sequence gaps fail the run. The boot gate checks
  retained boot history; if it has been overwritten, reboot before running.
- `pytest-timeout` gives test bodies 900 seconds; churn allows at least one hour
  for its minimum soak and a complete tuple rotation, or its configured duration
  plus 420 seconds if longer. `ARGS='--timeout=seconds'` changes
  the default. Operation and cleanup deadlines are separate so a timed-out
  body can still release resources. A hard-killed process cannot run cleanup.
- Select `host`, `hardware`, `smoke`, `slow`, and `destructive` with `ARGS='-m
  expression'`. Markers and configuration are checked strictly. Startup tests
  remain a separate `make test-startup` command and require their special boot.
- `ARGS=--release` checks required DUT tools before setup and fails on
  every selected skip, including disabled opt-in cases. Expected xfails keep
  their native status. Select the required release matrix explicitly and enable
  its opt-in cases. WAN address lifecycle needs its separate subnet invocation.
- `ARGS='--module-order-seed=42'` shuffles whole modules with the standard
  library. Test and parameter order within each module stays intact, including
  the shared profile lifecycles. Session artifacts record the seed and complete
  selection so a failing order can be repeated on the same boot.

Native lifecycle tests use the actual protocol daemons: `flowtable_dhcp.py`
checks unchanged renewal, renewal after the server loses its lease database,
and a new WAN lease; `flowtable_slaac.py` checks
advertised prefix deprecation, existing sockets and new source selection;
`flowtable_ike.py` negotiates IKEv2, rekeys a child SA and restarts its owned
peer. Their DHCP/RA segments and peer daemons are isolated test resources.
The IKE case requires UDP 500/4500 and the DUT's charon PID file to be unused.

`profile_homelab.py::test_mixed_traffic_survives_rekey` keeps the VLAN WAN paths,
IPv6 tunnel, IPsec and multicast active together for a minute through a rekey.
`flowtable_nat_throughput.py` checks a 9 Gbit/s TCP floor in separate forward and
reverse runs, simultaneous unpaced TCP directions with floors of 8 Gbit/s forward
and 6 Gbit/s reverse (the offloaded egress bound, A313), and 64-byte UDP payloads
at 25 Mbit/s. Artifacts include native DUT MAC
counters, endpoint NIC counters, UDP loss and receiver buffer errors. Native
iperf's reverse-only UDP stream does not meet the service's established
original-direction admission rule, so simultaneous throughput uses TCP.

`flowtable_jumbo.py` carries MTU 9000 on every hop: offloaded NAT TCP at
8 Gbit/s each way and byte-exact 8972-byte UDP, a VLAN at 9000, a LAN at 9000
behind a WAN at 1500 (TCP offloaded, oversized UDP fragmented by Linux, ICMP
and Packet Too Big), a live MTU change, and A316's regression: a jumbo host on
a 1500 port, whose frames the MAC drops and counts instead of the microcode
fragmenting them. It raises the WAN host's bridge to 9000 only after pinning
that host's own routes to 1500, refuses to start if a route carries metrics
of its own, and restores every MTU, route and IPv6 MTU on the same boot. The
WAN host's NIC itself stays at 9000 (its bridge at 1500), so no test bounces
its link.

The QoS host tests compile the production lifecycle functions with
AddressSanitizer and UndefinedBehaviorSanitizer, inject each startup
failure, and check resource balance, retries, interface reassignment,
queue selection, and pending rejection notifications. They require a host
C compiler and run without the board:

```sh
pytest -c tools/pyproject.toml tools/host_tests -k qos
```

The SDK regression uses the patched kernel source from the build tree.
Set `ASK_KERNEL_SOURCE` to test another patched tree. Missing SDK or vendor
sources fail the host suite with an actionable error; no SDK tests silently
skip. Build the image first to fetch and patch the required sources.
Forced-drain cases hold frames in a queue until timeout or fail its query,
then verify that pool buffers and skb-backed frames are reclaimed before
the interface context is released. Persistent hardware errors and prefetch
retries must return within the drain deadline. Undrained queues retain their
device references and policers until cleanup succeeds, and a failed queue
must not force-pop later queues that can drain normally. Terminal module
cleanup waits for hardware to release retained queues before unloading their
callbacks or freeing dependent pools; a permanent hardware failure requires
a board reset. This terminal wait is separate from bounded interface drains.
Both port and QoS shutdown release RTNL between attempts while retaining the
control mutex. Host faults verify that an unrelated netlink operation can
take RTNL during every retry wait and resources survive until recovery.
The SDK CQ-pop test checks command and
descriptor byte order, portal-result lifetime, prefetch retries, errors,
and a final response containing both a frame and the empty-queue flag.

The SDK host tests compile production port, scheme and state-query functions
under ASan/UBSan. They check ownership, cleanup, busy refusals and the
port enable/stopped/fence queries. They require the patched ASK kernel source.
Run them with:

```sh
make test-host K='sdk_port or sdk_scheme'
```

The userspace FMD ioctl plane these once also exercised is gone: cdx builds the
PCD in-kernel, so the character devices and their native/compat ioctl handlers
were removed with `fmc`/`fmlib`/`dpa_app`.

`tools/host_tests/sdk_port_pcd.py` also compiles the SDK port-setup and
classification-plan functions with their real private types. It checks
failures after classifier-root, plan and scheme binding, parser validation,
plan allocation and programming, shared owners, and retry on the same port.
These failures happen inside the SDK operations, beyond the ioctl boundary
mocked by the loader lifecycle test.

`tools/host_tests/sdk_port_resources.py` runs the actual FM allocator,
resource setters and register helpers under ASan/UBSan. It rejects exhausted
task/FIFO/DMA and dequeue budgets, checks MTU error exits, preserves another
port's allocations, and exercises retry, release, reset-derived DMA counts,
runtime FIFO resizing and guest failures. Every refusal must leave accounting,
registers and caller parameters unchanged, with the original interrupt state
restored. Both LS104x and legacy resource-accounting variants are compiled.

On the DUT, DPA tests verify that the control device `/dev/cdx_ctrl` excludes a
second opener, and that no FMan userspace character device (`/dev/fm*`) or `fm`
chardev major exists at all: the PCD is built in-kernel and the SDK's ioctl
plane was removed. USDPAA (`/dev/fsl-usdpaa*`) is not built either. Startup
fault injection requires a dedicated boot before CDX is loaded.

CDX startup rollback has a separate hardware test because it needs an
unconfigured FMAN. Boot the staged test image with `rdinit=/bin/sh`, mount
proc, sysfs, devtmpfs and debugfs, then run:

```sh
make test-startup
```

The cases use the Gateway DK's five Ethernet and two offline ports. They
inject failures after statistics allocation, interface creation, private
policer allocation, partial transmit/receive queue creation, shared
policer creation and the final classifier setup. Each failure must remove
CDX and its proc entries, restore the original MURAM free-space count,
and preserve the enable state of every active FMAN port.
The test checks kmemleak and kernel diagnostics, then loads and unloads CDX
normally in the same boot, checking port-state restoration and teardown
diagnostics. This is a quiescent unload. Afterwards, boot the staged image
again over TFTP with `rdinit=/bin/sh` removed from the boot arguments, then
run traffic tests. A plain reboot may select the board's installed firmware.

The fault controls `dpa_init_fail_site` and `dpa_init_fail_step` are built
only into the test image. Production builds omit them. Host coverage in
`tools/host_tests/cdx_startup.py` exercises the SET_PARAMS transaction,
partial userspace copies, allocation failures and asynchronous queue
retirement under ASan/UBSan. It also checks all initial port enable-state
combinations, state restoration after rollback and unload, and the production
unload cleanup of PCD queues, private/shared policers and FMAN metadata.
The SDK port API cases cover detach on policy-less and fully cleaned ports,
while incomplete setup and real hardware detach errors must still fail.
`sdk_port_state.py` compiles the production `FM_PORT_GetEnabled`/`GetStopped`/
`IsPcdAttached`/`SetFenced`/`Enable` functions directly, checking the port
enable and stopped queries, PCD attachment and the fence. Both partial-creation
rollback and complete interface teardown must drain all transmit queues and
finish callbacks before releasing their embedded FQ storage.
The queue model invokes the registered dequeue callback for contiguous and
scatter/gather frames and for completions without a valid frame descriptor.
It checks that every returned frame is released once and empty completions
release nothing, for both 8- and 16-queue configurations.

`make ask-test` runs pytest under `sudo` (it needs the serial PTYs and the
USB-serial nodes) against the source tree, so test edits are picked up
without a redeploy. An autouse fixture fails the run's hardware tests at setup
if the DUT agent does not answer. DUT control does not require an IP address.

---

## How the harness reaches each node

| Node | Transport | Used for |
|---|---|---|
| DUT | Persistent serial agent (UART, or USB CDC-ACM) | Commands, counters, kernel windows and local observations |
| WAN host | HTTP test agent | Orchestrator-host operations |
| LAN client | QEMU guest agent over virtio | Commands, scripts and local peer RPC |

The DUT opens no test-control TCP listener. The QoS control-traffic test creates
an explicit temporary TCP listener for its handshake measurement and closes it
at teardown. The multi-connection LAN peer uses a Unix socket for RPC inside
the VM; its traffic sockets still exercise the DUT normally.
QGA heartbeats keep that peer alive during quiet DUT measurements; its idle
lease still ends traffic if the runner disappears.

Agent messages use compressed JSON, checked fragments and acknowledgements.
Only damaged or unacknowledged fragments are retried. Completed request IDs are
not executed again. Missing results fail with an unknown outcome; the harness
does not replay a mutation. Scripts are cached by SHA-256 for the session.
An idle agent exits after five minutes without requests or running operations,
restoring the shell settings and console log level.

Capacity and churn snapshots stay on the DUT in a bounded SQLite store. Every
flow tuple, generation, counter and translation used by the assertions is
checked locally; the host receives counts and bounded mismatch samples. Entry
waits, tuple deletion batches and bulk-detach timing run locally too. Small
flowtables still return rows for the existing host assertions. Snapshot reads
are timed on the DUT.

Kernel windows drain locally throughout each test and report completeness,
sequence gaps and splat banners. Full logs stay in temporary artifacts; failed
tests retrieve them in checked chunks. Capacity/churn failures also retrieve
the last two retained raw snapshots as gzip files. Passing captures and released
snapshots are deleted. Budget exhaustion fails explicitly. Session exit removes
its temporary files; the boot recorder retains history separately.

## SDK host-command failure recovery

An enqueue rejection leaves the HC frame with the caller, restores its CPU
byte order, and permits another transport attempt. Acceptance and completion
are separate: the SDK waits up to one second for that command's confirmation.

`HC confirmation timed out; board reset required` means completion is
unknown. Stop PCD management operations and reboot the board before reusing
any affected hardware objects. The transport retains an unconfirmed frame,
rejects further commands, and refuses buffer replacement, teardown, or a
switch to direct register programming. A late confirmation releases the
frame only; it does not reconcile caller software state or reopen transport.
FMan sysfs bind/unbind is disabled because this built-in driver has no proven
DMA drain/reset path and its remove callback cannot veto devres cleanup.
Failed scheme modification preserves the previous software state; failed
creation leaves the scheme invalid. This does not establish hardware
rollback after an HC timeout; the board-reset requirement still applies.

`tools/host_tests/sdk_hc_transport.py` compiles the actual SDK pool,
enqueue, completion and cleanup helpers together with the Linux QMan wrapper
under ASan/UBSan. It injects rejection, missing and late confirmations,
completion at the deadline, overlapping commands, pool exhaustion and partial
allocation failure. Set `ASK_KERNEL_SOURCE` to a patched kernel tree, or use
the default build tree, and run it with the other host tests. Hardware smoke,
scheme lifecycle and offload tests cover normal confirmed commands; the
transport timeout injections run on the host.

## SDK scheme programming failures

`tools/host_tests/sdk_scheme_set.py` compiles the production register
builder, scheme set/delete paths, lock pool, netenv references and HC
transport under ASan/UBSan. It exercises lock/spinlock allocation failure,
early and late construction errors, extraction allocation failure, rejected
HC enqueues, direct-register errors and retry. Failed new schemes must leave
no saved lock or ownership; failed modifications must leave the existing
scheme and netenv references intact. A lock reassigned after failure must
remain untouched by stale deletion or retry.

Successful replacement transfers netenv ownership once, preserves bindings
and required-action bookkeeping, and publishes the newly built configuration
only after programming succeeds. The tests also overlap a second creator,
modification and binding attempt with programming. Accepted commands with
missing or late confirmations exercise the A117 reset requirement using the
actual HC transport; the fixture allows hardware to have changed despite
the timeout and verifies that retries cannot submit another command.

Kernel compilation must also be checked with `CONFIG_FORTIFY_SOURCE=y`,
warnings treated as errors, and KASAN disabled. On arm64, a KASAN build routes
uninstrumented SDK objects through `__memcpy` and disables FORTIFY for those
objects; the KASAN hardware run does not cover this compiler check.
