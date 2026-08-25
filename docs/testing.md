# ASK Test Bench Setup

This document describes how to set up the ASK end-to-end test bench from
scratch. It covers the physical/logical topology, what each machine needs,
how to reach the console of each node, and how to run the suite.

No addresses or hostnames appear here on purpose — every one is a
configuration value with a sane default and an environment-variable
override (see [Configuring the harness](#configuring-the-harness)). Fill in
your own addresses when you wire the bench.

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
  over its serial line and runs them (see `lan_run_python`).

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

Every node address is an environment variable with a default. Set the ones
that differ from your bench. `make ask-test` re-states `ASK_*` variables
across the `sudo` boundary automatically (use space-free values).

| Variable | What it points at | Default meaning |
|---|---|---|
| `ASK_TARGET_IP` | DUT test-agent host (HTTP) | on-DUT agent |
| `ASK_TARGET_DEV` | DUT serial device | USB-serial node |
| `ASK_TARGET_LAN_IF` | DUT netdev facing the client | LAN-facing port |
| `ASK_TARGET_WAN_IF` | DUT netdev facing the WAN | WAN-facing port |
| `ASK_LAN_VM` | libvirt domain of the client (VM case) | client domain |
| `ASK_LAN_USER` / `ASK_LAN_PASSWORD` | client serial login | client credentials |
| `ASK_LAN_NIC` | client's LAN-facing NIC name | client NIC |
| `ASK_WAN_IP` | WAN-side test-agent host (HTTP) | WAN host |
| `ASK_WAN_IPERF_IP` | iperf3 server on the WAN network | WAN iperf server |

## Running the suite

Prerequisites: the DUT is on the test image with its agent responding, the
WAN agent is deployed, the WAN iperf3 server is up, and no manual session is
holding either serial console.

```sh
# full suite (re-state your bench's addresses)
ASK_WAN_IP=<wan-host> ASK_WAN_IPERF_IP=<wan-iperf> make ask-test

# a scoped subset while iterating
make ask-test ASK_TEST_ARGS='-k "ipsec or mcast"'
```

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
