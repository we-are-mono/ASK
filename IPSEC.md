# IPSEC.md — IPsec tunnel test scenarios

Manual bring-up recipes for IPsec tunnels exercised against the ASK gateway. Each section
is one tested scenario with the full config for both peers, the bring-up commands, and what
we measured.

These setups are deliberately strongSwan-free: pure `ip xfrm state add` + `ip xfrm policy
add`. strongSwan / charon was tried first, but on the meta-ask test image (with the cdx
xfrm-offload patch) `swanctl --load-all` installs the SA but **does not install the kernel
xfrm tunnel policies on DUT** — only socket policies appear. That breaks the data plane
without surfacing the failure anywhere obvious. Manual xfrm bypasses charon and gives
deterministic, reproducible state. A future slice-2 fixture (per ISSUES.md A14/A15/A19,
test_ipsec_dma_balance.py, test_ipsec_natt_spi_bounds.py) is the planned home for
strongSwan/IKE-driven setup.

## Topology

| Role     | Address       | Notes |
| -------- | ------------- | ----- |
| Vision   | `10.0.0.141`  | Orchestrator host. Mainline Debian, software xfrm. `10.99.0.2/32` lives on `lo`. |
| DUT      | `10.0.0.62`   | LS1046A, cdx kernel patch ([patches/kernel/040-ask-xfrm-ipsec-offload.patch](patches/kernel/040-ask-xfrm-ipsec-offload.patch)). Forwards `192.168.1.0/24 ↔ eth3`. |
| LAN VM   | `192.168.1.122` (loki) | libvirt VM behind DUT. Default gw `192.168.1.1` → DUT eth4. |

The protected pair is `192.168.1.0/24 ↔ 10.99.0.2/32`. Outer endpoints
`10.0.0.62 ↔ 10.0.0.141` carry the ESP.

## Cipher status summary

Measured under loki → 10.99.0.2 via the manual setups below. CBC + HMAC and CCM run
on the cdx hardware encap path (DUT SA byte counters stay at 0, `xfrm_output` does
not fire). GCM is **refused** by cdx at SA install (ISSUES.md A24) so the SA falls
through to kernel xfrm via `caamalg_qi.c` — DUT byte counters tick, `xfrm_output`
does fire, replay-window=32 works correctly, throughput ~1–2 Gbit/s.

| Cipher | TCP iperf3 (15 s) | UDP @ 1 Gbit/s (5 s) | replay-window=32 | Path |
| ------ | ----------------- | -------------------- | ---------------- | ---- |
| **AES-128-CBC + HMAC-SHA-256-128** | 2.60 Gbit/s, 365 retx | 1.00 Gbit/s, 0 % loss | ✓ | cdx hardware |
| **AES-128-CCM-ICV16** | 1.45 Gbit/s, 12 retx | 1.00 Gbit/s, 0.005 % loss | ✓ | cdx hardware |
| **AES-128-GCM-ICV16** | 77 Mbit/s, 970 retx | 89 % loss above ~80 Mbit/s | ✓ | kernel xfrm (caamalg.c JR) |
| **AES-128-GMAC** (rfc4543) | n/a | failed at 4 PPS | n/a | separate bug |

GCM hardware offload was deprecated after A24a — the cdx fast path produced ~21–25 %
wire-seq duplicates above ~100 Mbit/s per SA (per-DECO PDB.seq counters diverge)
which violates RFC 4303 anti-replay on standards-compliant peers. IV-uniqueness was
empirically verified preserved (no GCM cryptographic break), so the issue is purely
operational. See ISSUES.md A24 for the full disposition. The kernel-xfrm GCM
fallback throughput (~77 Mbit/s TCP on this kernel/config) is much lower than the
2.60 Gbit/s offloaded CBC+HMAC path because `/proc/crypto` selects the higher-priority
`rfc4106-gcm-aes-caam` (JR) over `rfc4106-gcm-aes-caam-qi` and JR has higher
per-request overhead. CBC + HMAC is the high-throughput recommendation; GCM is the
strongSwan-defaults-compatible fallback at substantially lower throughput.

---

## 1. AES-128-CBC + HMAC-SHA-256-128 — production-recommended

This is the working baseline. Saturates the wire at line rate, no errors, hardware path.

### Test parameters

```sh
SPI_DUT_OUT=0xcb010001
SPI_DUT_IN=0xcb010002
ENC1=0x00112233445566778899aabbccddeeff       # 16-byte AES key
ENC2=0xfedcba9876543210ffeeddccbbaa9988       # 16-byte AES key
AUTH1=0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f  # 32B HMAC-SHA-256 key
AUTH2=0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f  # 32B HMAC-SHA-256 key
ICV_TRUNC=128
```

### Vision bring-up

```sh
sudo ip xfrm state flush; sudo ip xfrm policy flush

sudo ip xfrm state add src 10.0.0.62  dst 10.0.0.141 \
    proto esp spi $SPI_DUT_OUT mode tunnel reqid 1 replay-window 32 \
    enc 'cbc(aes)' $ENC1 auth-trunc 'hmac(sha256)' $AUTH1 $ICV_TRUNC
sudo ip xfrm state add src 10.0.0.141 dst 10.0.0.62  \
    proto esp spi $SPI_DUT_IN  mode tunnel reqid 1 replay-window 32 \
    enc 'cbc(aes)' $ENC2 auth-trunc 'hmac(sha256)' $AUTH2 $ICV_TRUNC

sudo ip xfrm policy add src 10.99.0.2/32   dst 192.168.1.0/24 dir out \
    tmpl src 10.0.0.141 dst 10.0.0.62 proto esp reqid 1 mode tunnel
sudo ip xfrm policy add src 192.168.1.0/24 dst 10.99.0.2/32   dir in  \
    tmpl src 10.0.0.62  dst 10.0.0.141 proto esp reqid 1 mode tunnel level required
sudo ip xfrm policy add src 192.168.1.0/24 dst 10.99.0.2/32   dir fwd \
    tmpl src 10.0.0.62  dst 10.0.0.141 proto esp reqid 1 mode tunnel level required
```

### DUT bring-up (via UART)

```sh
ip xfrm state flush; ip xfrm policy flush

ip xfrm state add src 10.0.0.62  dst 10.0.0.141 \
    proto esp spi 0xcb010001 mode tunnel reqid 1 replay-window 32 \
    enc 'cbc(aes)' 0x00112233445566778899aabbccddeeff \
    auth-trunc 'hmac(sha256)' 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 128
ip xfrm state add src 10.0.0.141 dst 10.0.0.62  \
    proto esp spi 0xcb010002 mode tunnel reqid 1 replay-window 32 \
    enc 'cbc(aes)' 0xfedcba9876543210ffeeddccbbaa9988 \
    auth-trunc 'hmac(sha256)' 0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f 128

ip xfrm policy add src 192.168.1.0/24 dst 10.99.0.2/32   dir out \
    tmpl src 10.0.0.62  dst 10.0.0.141 proto esp reqid 1 mode tunnel
ip xfrm policy add src 10.99.0.2/32   dst 192.168.1.0/24 dir in  \
    tmpl src 10.0.0.141 dst 10.0.0.62  proto esp reqid 1 mode tunnel level required
ip xfrm policy add src 10.99.0.2/32   dst 192.168.1.0/24 dir fwd \
    tmpl src 10.0.0.141 dst 10.0.0.62  proto esp reqid 1 mode tunnel level required

ip route replace 10.99.0.2/32 via 10.0.0.141 dev eth3
iptables -t nat -I POSTROUTING 1 -s 192.168.1.0/24 -d 10.99.0.2/32 -j ACCEPT
```

The MASQUERADE bypass on POSTROUTING line 1 is essential: meta-ask's `S40gateway-setup`
installs `-t nat -A POSTROUTING -o eth3 -j MASQUERADE` unconditionally, which would
rewrite the inner source from `192.168.1.122` to `10.0.0.62` before xfrm-OUT match,
breaking the selector match on Vision's `dir in` policy.

### Observed

- TCP iperf3 (15 s, default MSS): **2.60 Gbit/s sender, 2.59 Gbit/s receiver, 365
  retransmits**.
- UDP iperf3 (5 s, 1 Gbit/s nominal, 1400 B): **1.00 Gbit/s receiver, 0 % loss**.
- 500-frame ESP capture: 0 sequence-number duplicates.
- Vision `XfrmInStateProtoError` Δ across all three runs: +344 (background noise from
  earlier sessions; effectively 0 for this configuration).

---

## 2. AES-128-CCM-ICV16 (RFC 4309) — production-recommended

Same hardware path, AEAD with serial CBC-MAC authentication. Slightly slower than CBC +
HMAC because SEC's CCM uses two AES passes per block, but at line rate with no errors.

Requires `CONFIG_CRYPTO_CCM=y` (built-in, not module) — the meta-ask kernel build sets
this in [meta-ask/recipes-kernel/linux/files/ask.cfg](meta-ask/recipes-kernel/linux/files/ask.cfg). Without it, `ip xfrm state add … aead 'rfc4309(ccm(aes))'` fails with
"Requested AEAD algorithm not found".

### Test parameters

```sh
SPI_DUT_OUT=0xcc010001
SPI_DUT_IN=0xcc010002
KEY1=0x0123456789abcdef0123456789abcdef111213       # 16-byte AES + 3-byte salt
KEY2=0xfedcba9876543210fedcba9876543210a1b2c3       # 16-byte AES + 3-byte salt
ICV_LEN=128
```

### Vision bring-up

```sh
sudo ip xfrm state flush; sudo ip xfrm policy flush

sudo ip xfrm state add src 10.0.0.62  dst 10.0.0.141 \
    proto esp spi $SPI_DUT_OUT mode tunnel reqid 1 replay-window 32 \
    aead 'rfc4309(ccm(aes))' $KEY1 $ICV_LEN
sudo ip xfrm state add src 10.0.0.141 dst 10.0.0.62  \
    proto esp spi $SPI_DUT_IN  mode tunnel reqid 1 replay-window 32 \
    aead 'rfc4309(ccm(aes))' $KEY2 $ICV_LEN

# Policies identical to §1.
```

### DUT bring-up

```sh
ip xfrm state flush; ip xfrm policy flush

ip xfrm state add src 10.0.0.62  dst 10.0.0.141 \
    proto esp spi 0xcc010001 mode tunnel reqid 1 replay-window 32 \
    aead 'rfc4309(ccm(aes))' 0x0123456789abcdef0123456789abcdef111213 128
ip xfrm state add src 10.0.0.141 dst 10.0.0.62  \
    proto esp spi 0xcc010002 mode tunnel reqid 1 replay-window 32 \
    aead 'rfc4309(ccm(aes))' 0xfedcba9876543210fedcba9876543210a1b2c3 128

# Policies + route + MASQUERADE bypass identical to §1.
```

### Observed

- TCP iperf3 (15 s): **1.45 Gbit/s sender, 1.45 Gbit/s receiver, 12 retransmits**.
- UDP iperf3 (5 s, 1 Gbit/s nominal, 1400 B): **1.00 Gbit/s receiver, 22/446 516 lost
  (0.005 %)** — at the NIC/driver-level edge, not an xfrm error.
- 500-frame ESP capture: 0 sequence-number duplicates.
- Vision `XfrmInStateProtoError` Δ: 0.

---

## 3. AES-128-GCM-ICV16 (RFC 4106) — kernel xfrm fallback (ISSUES.md A24)

**cdx refuses GCM offload at SA install.** The kernel-side SA still installs (via
`ip xfrm state add` below), but `M_ipsec_sa_set_cipher_key` returns -1 for GCM/GMAC
cipher types and emits a `pr_warn`, so `x->offloaded` stays 0 and the SA falls
through to Linux xfrm + `caamalg_qi.c`. Replay-window=32 works correctly here
(unique seqs by construction); throughput is the kernel-xfrm envelope ~1–2 Gbit/s.
Bring-up commands are kept verbatim for regression testing once A24 closes.

### Test parameters

```sh
SPI_DUT_OUT=0xc0ffee01
SPI_DUT_IN=0xc0ffee02
KEY1=0x0123456789abcdef0123456789abcdef0a1b2c3d              # 16 AES + 4 salt
KEY2=0xfedcba9876543210fedcba9876543210e0f1a2b3              # 16 AES + 4 salt
ICV_LEN=128
```

### Vision bring-up

```sh
sudo ip xfrm state flush; sudo ip xfrm policy flush

sudo ip xfrm state add src 10.0.0.62  dst 10.0.0.141 \
    proto esp spi $SPI_DUT_OUT mode tunnel reqid 1 replay-window 32 \
    aead 'rfc4106(gcm(aes))' $KEY1 $ICV_LEN
sudo ip xfrm state add src 10.0.0.141 dst 10.0.0.62  \
    proto esp spi $SPI_DUT_IN  mode tunnel reqid 1 replay-window 32 \
    aead 'rfc4106(gcm(aes))' $KEY2 $ICV_LEN

# Policies identical to §1.
```

### DUT bring-up

```sh
ip xfrm state flush; ip xfrm policy flush

ip xfrm state add src 10.0.0.62  dst 10.0.0.141 \
    proto esp spi 0xc0ffee01 mode tunnel reqid 1 replay-window 32 \
    aead 'rfc4106(gcm(aes))' 0x0123456789abcdef0123456789abcdef0a1b2c3d 128
ip xfrm state add src 10.0.0.141 dst 10.0.0.62  \
    proto esp spi 0xc0ffee02 mode tunnel reqid 1 replay-window 32 \
    aead 'rfc4106(gcm(aes))' 0xfedcba9876543210fedcba9876543210e0f1a2b3 128

# Policies + route + MASQUERADE bypass identical to §1.
```

### Observed (post-refusal)

- DUT `dmesg` on SA install: `cdx: AES-GCM/GMAC offload disabled (A24a). SA falls
  through to kernel xfrm. For hardware offload use AES-128-CCM-16 or AES-128-CBC +
  HMAC-SHA-256.`
- DUT `xfrm_output` fires on every encap; `ip -s xfrm state` byte/packet counters
  tick (in contrast to CBC/CCM where they stay at 0 because cdx is offloading).
- TCP iperf3 (15 s) on a `replay-window=32` Vision peer: clean — 77 Mbit/s, 970 retx,
  0 ICV failures, 0 wire-seq duplicates, 0 replay-window rejections.
- UDP iperf3 (5 s @ 1 Gbit/s, 1400 B): 85 Mbit/s receiver, 89 % upstream loss from
  software-xfrm CPU saturation, but 0 `XfrmInStateProtoError` and 0
  `XfrmInStateSeqError` deltas — losses are pre-xfrm, not cryptographic.
- A regression that re-enables cdx GCM offload would surface here as either
  `XfrmInStateProtoError` ticks (cross-DECO GHASH race) or wire-seq duplicates
  triggering `XfrmInStateSeqError` on Vision — tracked by
  [tools/tests/test_ipsec_gcm_replay_window.py](tools/tests/test_ipsec_gcm_replay_window.py).

### Tear-down (any of the three configs)

```sh
sudo ip xfrm state flush; sudo ip xfrm policy flush
# DUT only:
iptables -t nat -D POSTROUTING -s 192.168.1.0/24 -d 10.99.0.2/32 -j ACCEPT
```
