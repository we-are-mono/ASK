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
The bench is three roles. They can be three physical machines, or (as we
run it) one workstation acting as the orchestrator with the client as a
local VM on it.

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
                  │ USB-serial to DUT                        │
                  │ serial/PTY to client                     │ DHCP-served
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
  the serial links to both the DUT and the client. In our lab this is a
  single Linux workstation.

- **DUT** — the LS1046A-class gateway under test. It runs the ASK test
  image (TFTP-booted). It has (at least) a **WAN-facing** port on the
  orchestrator/WAN segment and a **LAN-facing** port to the client. It runs
  a DHCP server + NAT on the LAN side, exactly like the shipping product.

- **LAN client** — a machine or VM cabled to the DUT's LAN port. It is a
  plain **DHCP client**: it takes its address from the DUT and lives behind
  the DUT's NAT. The traffic tests originate/sink here. In our lab this is a
  libvirt VM on the orchestrator host, but any machine on the DUT's LAN port
  works.

The key asymmetry that shapes everything below: **the client is only
reachable over its serial console, never over the network.** It sits behind
the DUT's NAT, so the orchestrator has no IP route to it. All LAN-side test
work is scripted over the client's serial line.

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
| `aiohttp` | HTTP agent and orchestrator client |
| `pyserial` | DUT and LAN serial consoles |
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
| Python harness checks in `tools/host_tests/test_harness.py` | Runner environment only; no board or compiler |
| Compiled host regressions | C/C++ compiler, headers, standard C++ library, AddressSanitizer and UndefinedBehaviorSanitizer; Debian's `build-essential` toolchain supplies these. `HOSTCC` selects a compiler instead of `cc`. |
| SDK/FMC/FMLIB host regressions | Patched kernel and pinned vendor source trees from the image build. `ASK_KERNEL_SOURCE` overrides the kernel tree; it must contain the ASK patches and SDK headers. |
| DUT traffic tests | WAN agent, `ip`/`bridge`/`tc`, `iptables`, `conntrack`, `ethtool`, `iperf3`, `tcpdump`, and access to the DUT and LAN consoles |
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
  host. `virsh` is used to open the client's serial console.
- **`python3` + `venv`** — for the WAN-side test agent and the pytest
  virtualenv (`make deploy-agent-wan` bootstraps the venv and installs the
  agent's requirements).
- **A USB-to-serial adapter** to the DUT's console header, plus permission
  to read it (the `dialout`/`plugdev` group, or run under `sudo`).
- Membership in the `libvirt`/`kvm` groups if the client is a local VM.

Test agent: `make deploy-agents` installs the WAN-side agent as a systemd
service and brings it up. Verify with a health check against the agent port
on loopback.

### DUT

Nothing to install — the ASK test image carries everything (the on-DUT test
agent auto-starts at boot). You only need to:

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
`capture_protocol: 2` in `/health`, readable `/dev/kmsg`, and retained boot logs.
After agent changes, rebuild, stage and boot the updated image. Preflight rejects
an older agent; installing host packages cannot upgrade the agent inside the
DUT's initramfs. Release runs also require the tools named by selected tests.

### LAN client

A machine or VM on the DUT's LAN port, configured as a **DHCP client** so it
picks up its address, gateway, and DNS from the DUT. Install:

- A **DHCP client** (whatever your distro ships — `dhcpcd`, `udhcpc`,
  `dhclient`, `systemd-networkd`, or `NetworkManager`), bringing up the
  LAN-facing NIC automatically at boot.
- **`iperf3`** — the LAN endpoint for throughput tests (it runs both as a
  client toward the WAN server and, for some tests, as a server).
- **`tcpdump`** — the LAN-side capture tool the tests grep for expected
  frames.
- **`iproute2`** (`ip`) — interface/route/neighbor manipulation.
- **`python3`** — the harness stages small Python snippets to the client
  over its serial line and runs them (see `lan_run_python`). Namespace cases
  need Python 3.12 or newer for `os.setns`; Python 3.13 matches the runner.
- **Scapy for the LAN's system `python3`** — used by the staged ARP and packet
  helpers. Installing it in the orchestrator's virtualenv does not install it
  on the LAN client.
- **`ethtool`, `coreutils`, `procps`, `psmisc`** — link statistics, script
  staging, timeouts and process cleanup.

For a Debian 13 LAN VM with its DHCP client already configured:

```sh
sudo apt-get install -y python3 python3-scapy iproute2 iputils-ping iperf3 \
    tcpdump ethtool coreutils procps psmisc
```

The configured serial login must have root access for namespaces, interface
changes and raw sockets.

The client must also expose a **serial console** the orchestrator can open
(see below). For a libvirt VM this is the domain's serial device; for a
physical client, a real serial port cabled to the orchestrator.

---

## Console / serial access

The harness bootstraps and drives both the DUT and the client over their
**serial consoles**, with no network prerequisite. This is what makes it
robust across reboots, NAT, and a downed network.

### DUT console

- USB-to-serial adapter to the DUT's console header.
- **115200 baud, 8N1.**
- Appears on the orchestrator as a character device (e.g. a `/dev/ttyUSB*`
  node). Reading it needs the `dialout`/`plugdev` group or `sudo`.
- Interactively: `tio <device>` (or any serial terminal).
- The harness opens it via `Console.target()`.

### Client console

- If the client is a **libvirt VM**: its serial console is a host PTY,
  resolved with `virsh ttyconsole <domain>` (which prints a `/dev/pts/N`
  path). `QEMU:///system` needs root, so this typically runs under `sudo`.
  Interactively: `tio $(sudo virsh ttyconsole <domain>)`.
- If the client is **physical**: a serial cable to the orchestrator, same
  idea as the DUT.
- The harness opens it via `Console.lan()`.

**One reader per serial line.** A serial console tolerates exactly one
reader. If you leave an interactive terminal (or a stray `cat`) attached to
a console, the harness's reads will come back garbled or time out. Detach
any manual session before running the suite — the suite drives both
consoles itself.

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

For a release-gate (memory-safety) run, build with KASAN instrumentation:

```sh
KASAN=1 make ask-image && make stage-image
```

## Booting the image

The DUT TFTP-boots the staged image from U-Boot — it is **not** flashed. At
the DUT's U-Boot prompt (interrupt autoboot over the serial console), run
the board's `ask` boot flow, which TFTPs the image from the orchestrator and
boots it in RAM. Point U-Boot's environment at your TFTP server's address
and the staged image name.

The root filesystem is an initramfs, so **every boot is clean** — on-DUT
changes do not persist across a reboot. The on-DUT test agent auto-starts;
confirm it responds before running tests.

---

## Configuring the harness

Put the bench IPs, VM name and client NIC in the ignored `.ask-test.mk` so
plain `make test` reuses them. Environment variables and make command-line
assignments can override that file. `ASK_*` variables pass through sudo
without shell interpolation, including values with spaces.

| Variable | What it points at | Setting |
|---|---|---|
| `DUT_IP` / `ASK_TARGET_IP` | DUT test-agent host (HTTP) | Required |
| `ASK_TARGET_DEV` | DUT serial device | Required |
| `ASK_TARGET_LAN_IF` | DUT netdev facing the client | Board default: `eth3` |
| `ASK_TARGET_WAN_IF` | DUT netdev facing the WAN | Board default: `eth4` |
| `ASK_LAN_VM` | libvirt domain of the client | Required |
| `ASK_LAN_USER` / `ASK_LAN_PASSWORD` | client serial login | `root` / no password |
| `ASK_LAN_NIC` | client's LAN-facing NIC name | Required |
| `ASK_WAN_INJECT_IF` | WAN interface for packet injection | Required for multicast and profiles |
| `WAN_AGENT_IP` / `ASK_WAN_IP` | WAN-side test-agent host (HTTP) | `WAN_IP`, or loopback for direct pytest |
| `WAN_IP` / `ASK_WAN_IPERF_IP` | Traffic endpoint on the WAN network | Required |

## Running the suite

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
holding either serial console. The image boots only the flowtable offload
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
`SKIPPED` status, followed by final totals. Successful-test stdout stays
captured; failures include their diagnostics. `ARGS=-s` explicitly enables
live output for debugging.

Each invocation creates a unique directory under `/tmp/ask-tests-<uid>` (override
with `ASK_TEST_ARTIFACTS`; `ASK_FLOWTABLE_ARTIFACTS` remains supported).
The final output prints its path. It contains `junit.xml`, session metadata
(revision, dependency versions, configured endpoints), DUT kernel/boot details,
boot logs, and one directory per test with setup/call/teardown results and
diagnostic artifacts. Test names include a hash so parameterized cases cannot
overwrite each other. Shared module captures and the LAN UART transcript
cover their corresponding fixture lifetimes. `ARGS='--junitxml=path.xml'`
chooses another JUnit destination. Parallel host workers share the run directory.

### Lifecycle and suite groups

- Shared code lives in `ask_orch` and `_*.py` support modules. Register shared
  fixtures in `conftest.py`; tests request fixtures by parameter name. Reuse
  scenarios through support functions, preserving each test's own identity.
- Register restoration immediately after acquiring a resource, before the
  next mutation. `CleanupStack` runs every undo in reverse order with a
  separate 45-second budget per callback and reports all failures. Commands
  must check return codes or verify an explicit cleanup postcondition.
- A hardware setup or teardown failure blocks later hardware cases in that
  invocation. Recover the bench before starting a new run. Hardware commands
  stop at the first failure by default; host commands report all failures.
- Local process locks cover the DUT, serial device, LAN VM and WAN endpoint.
  Overlapping invocations fail before setup; hardware xdist workers are
  rejected. Locks cover runners on one orchestrator. A shared lab coordinator
  is needed if several orchestrators can access the same physical bench.
- Kernel capture is automatic around each DUT test and its function fixtures.
  The two module-scoped profiles also capture setup and teardown. Missing
  logs, ring overruns and sequence gaps fail the run. The boot gate checks
  retained boot history; if it has been overwritten, reboot before running.
- `pytest-timeout` gives test bodies 900 seconds; the churn case uses its
  configured duration plus 300 seconds. `ARGS='--timeout=seconds'` changes
  the default. Operation and cleanup deadlines are separate so a timed-out
  body can still release resources. A hard-killed process cannot run cleanup.
- Select `host`, `hardware`, `smoke`, `slow`, and `destructive` with `ARGS='-m
  expression'`. Markers and configuration are checked strictly. Startup tests
  remain a separate `make test-startup` command and require their special boot.
- `ARGS=--release` checks required DUT tools before setup and fails on
  unexpected skips. Explicitly disabled opt-in cases and expected xfails keep
  their native status. Select the required release matrix explicitly, including
  the appropriate environment settings for opt-in cases.

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

The DPA host lifecycle test compiles the pinned FMC and FMLIB sources with
our patches and the production loader under ASan/UBSan. It injects startup
allocation/device failures and cleanup failures, checks retries and shared
object ownership, and exercises saved-model compatibility and one/two-FMAN
table counts. The companion SDK test exercises external-table teardown,
root ownership, shared cookies, busy refusals, and stale handles. Compat hash
copy-out failures release new cookies; refused deletes and shared handles
retain their mappings. Legacy root retargeting is rejected at the SDK and
fmlib boundaries, as it already was at the ioctl boundary. SDK and
fmlib tests reject hardware-reassembly creation/attachment before allocations
or nested-handle access; native and compat ioctl tests cover reserved inputs.
These tests require the fetched vendor Git repositories and the patched ASK
kernel source. Run them with:

```sh
pytest -c tools/pyproject.toml tools/host_tests/test_dpa_lifecycle.py
```

`tools/host_tests/test_sdk_port_pcd.py` also compiles the SDK port-setup and
classification-plan functions with their real private types. It checks
failures after classifier-root, plan and scheme binding, parser validation,
plan allocation and programming, shared owners, and retry on the same port.
These failures happen inside the SDK operations, beyond the ioctl boundary
mocked by the loader lifecycle test.

`tools/host_tests/test_sdk_port_resources.py` runs the actual FM allocator,
resource setters and register helpers under ASan/UBSan. It rejects exhausted
task/FIFO/DMA and dequeue budgets, checks MTU error exits, preserves another
port's allocations, and exercises retry, release, reset-derived DMA counts,
runtime FIFO resizing and guest failures. Every refusal must leave accounting,
registers and caller parameters unchanged, with the original interrupt state
restored. Both LS104x and legacy resource-accounting variants are compiled.

On the DUT, DPA tests verify that repeated loader invocations stop at the
initialization check, that the control device excludes a second opener,
and that the new check obeys the per-ioctl capability gate. They also create
and delete unused hash tables, reject stale cookies, and check that failed
copy-out does not exhaust the cookie registry. Startup fault injection
requires a dedicated boot before CDX is loaded.

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
`tools/host_tests/test_cdx_startup.py` exercises the SET_PARAMS transaction,
partial userspace copies, allocation failures and asynchronous queue
retirement under ASan/UBSan. It also checks all initial port enable-state
combinations, state restoration after rollback and unload, and the production
unload cleanup of PCD queues, private/shared policers and FMAN metadata.
The SDK port API cases cover detach on policy-less and fully cleaned ports,
while incomplete setup and real hardware detach errors must still fail.
The FMC lifecycle test preserves initially disabled ports on both successful
cleanup and failed loads. `test_sdk_port_state.py` compiles the port-state
query API and ioctl dispatch for native and compat callers, checking the
one-byte result and error propagation. The new `FM_PORT_IOC_GET_ENABLED`
command uses port ioctl slot 44; existing encodings are unchanged. FMC saved
models use format version `0x108` to include the saved enable-state flags. Both partial-creation rollback and complete
interface teardown must drain all transmit queues and finish callbacks
before releasing their embedded FQ storage.
The queue model invokes the registered dequeue callback for contiguous and
scatter/gather frames and for completions without a valid frame descriptor.
It checks that every returned frame is released once and empty completions
release nothing, for both 8- and 16-queue configurations.

`make ask-test` runs pytest under `sudo` (it needs the serial PTYs and the
USB-serial node) against the source tree, so test edits are picked up
without a redeploy. An autouse fixture fail-fasts the whole run if the DUT
agent does not answer, so a misconfigured `ASK_TARGET_IP` stops you
immediately rather than deep into the run.

---

## How the harness reaches each node

Three transports, one purpose each — never cross them:

| Node | Transport | Used for |
|---|---|---|
| DUT | HTTP test agent | DUT operations (exec allowlist, counters, kmemleak) |
| WAN host | HTTP test agent | orchestrator-host operations |
| LAN client | serial console only | all LAN-side work (no IP path exists) |

Because the client has no IP route from the orchestrator, LAN-side steps go
through its serial console: the harness stages a snippet to the client over
serial and runs it (`lan_run_python` for Python; backgrounded shell
processes coordinated through the client's filesystem for parallel-shape
work). Do not look for an HTTP agent on the client — there isn't one, by
design.

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

`tools/host_tests/test_sdk_hc_transport.py` compiles the actual SDK pool,
enqueue, completion and cleanup helpers together with the Linux QMan wrapper
under ASan/UBSan. It injects rejection, missing and late confirmations,
completion at the deadline, overlapping commands, pool exhaustion and partial
allocation failure. Set `ASK_KERNEL_SOURCE` to a patched kernel tree, or use
the default build tree, and run it with the other host tests. Hardware smoke,
scheme lifecycle and offload tests cover normal confirmed commands; the
transport timeout injections run on the host.

## SDK scheme programming failures

`tools/host_tests/test_sdk_scheme_set.py` compiles the production register
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

On the DUT, the ordinary/direct scheme lifecycle regression in
`tools/tests/test_dpa_startup.py` includes a late construction failure with
an out-of-range FQID. For an ordinary scheme the rejected candidate changes
to direct mode; deleting the original immediately afterward must still
release its original netenv reference. These are private, unbound schemes.

`tools/host_tests/test_sdk_scheme_ioctl.py` checks native/compat conversion and
fmlib serialization under ASan/UBSan, with compiler member-bound checks on
every `memcpy`. It covers DONE, CC and policer next engines, the trailing
scheme counter, public cookies, direct/shared flags and allocation failures.
Reverting either enclosing-object tail copy or the compat source-union bound
must fail compilation, even when the host libc only checks whole objects.

Kernel compilation must also be checked with `CONFIG_FORTIFY_SOURCE=y`,
warnings treated as errors, and KASAN disabled. On arm64, a KASAN build routes
uninstrumented SDK objects through `__memcpy` and disables FORTIFY for those
objects; the KASAN hardware run does not cover this compiler check.
