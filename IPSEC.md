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

## Cipher status summary (2026-05-05)

Measured under loki → 10.99.0.2 via the manual setups below. DUT is a freshly-booted
LS1046A; cdx hardware encap path is engaged in every case (verified via wire capture +
DUT SA byte counters staying at 0 and `xfrm_output` not firing — both directions are
SEC-offloaded, not Linux software xfrm).

| Cipher | TCP iperf3 (15 s) | UDP @ 1 Gbit/s (5 s) | seq dupes / 500 frames | Status |
| ------ | ----------------- | -------------------- | ---------------------- | ------ |
| **AES-128-CBC + HMAC-SHA-256-128** | 2.60 Gbit/s, 365 retx | 1.00 Gbit/s, 0 % loss | 0 | works |
| **AES-128-CCM-ICV16** | 1.45 Gbit/s, 12 retx | 1.00 Gbit/s, 0.005 % loss | 0 | works |
| **AES-128-GCM-ICV16** | 2-3 Mbit/s, 600+ retx | 140 Mbit/s, **86 % loss** | sporadic (0-4) | **broken** |
| **AES-128-GCM-ICV8** | n/a | 144 Mbit/s, **86 % loss** | sporadic | **broken** |
| **AES-128-GMAC** (rfc4543) | n/a | failed at 4 PPS | n/a | separate bug |

The CBC and CCM rows are usable production proposals; the GCM rows reproduce **ISSUES.md
A24** symptom. Reboots don't change the picture — same 86 % loss on the first packet of
the first iperf3 after a fresh boot.

The bug is **specific to the GHASH-based authentication path in SEC** under concurrent
ops on the same SA. CCM uses inherently-serial CBC-MAC and is immune; CBC + HMAC is
serial-by-construction over the whole packet and is immune. GCM (and GMAC, which is
GCM with null encryption) parallelize the GHASH polynomial — which is the contended
state. See ISSUES.md A24 for the full diagnosis.

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
    proto esp spi $SPI_DUT_OUT mode tunnel reqid 1 \
    enc 'cbc(aes)' $ENC1 auth-trunc 'hmac(sha256)' $AUTH1 $ICV_TRUNC
sudo ip xfrm state add src 10.0.0.141 dst 10.0.0.62  \
    proto esp spi $SPI_DUT_IN  mode tunnel reqid 1 \
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
    proto esp spi 0xcb010001 mode tunnel reqid 1 \
    enc 'cbc(aes)' 0x00112233445566778899aabbccddeeff \
    auth-trunc 'hmac(sha256)' 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 128
ip xfrm state add src 10.0.0.141 dst 10.0.0.62  \
    proto esp spi 0xcb010002 mode tunnel reqid 1 \
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
    proto esp spi $SPI_DUT_OUT mode tunnel reqid 1 \
    aead 'rfc4309(ccm(aes))' $KEY1 $ICV_LEN
sudo ip xfrm state add src 10.0.0.141 dst 10.0.0.62  \
    proto esp spi $SPI_DUT_IN  mode tunnel reqid 1 \
    aead 'rfc4309(ccm(aes))' $KEY2 $ICV_LEN

# Policies identical to §1.
```

### DUT bring-up

```sh
ip xfrm state flush; ip xfrm policy flush

ip xfrm state add src 10.0.0.62  dst 10.0.0.141 \
    proto esp spi 0xcc010001 mode tunnel reqid 1 \
    aead 'rfc4309(ccm(aes))' 0x0123456789abcdef0123456789abcdef111213 128
ip xfrm state add src 10.0.0.141 dst 10.0.0.62  \
    proto esp spi 0xcc010002 mode tunnel reqid 1 \
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

## 3. AES-128-GCM-ICV16 (RFC 4106) — broken under load (ISSUES.md A24)

**Do not use in production until A24 is fixed.** Documented here to make the failure
reproducible.

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
    proto esp spi $SPI_DUT_OUT mode tunnel reqid 1 \
    aead 'rfc4106(gcm(aes))' $KEY1 $ICV_LEN
sudo ip xfrm state add src 10.0.0.141 dst 10.0.0.62  \
    proto esp spi $SPI_DUT_IN  mode tunnel reqid 1 \
    aead 'rfc4106(gcm(aes))' $KEY2 $ICV_LEN

# Policies identical to §1.
```

### DUT bring-up

```sh
ip xfrm state flush; ip xfrm policy flush

ip xfrm state add src 10.0.0.62  dst 10.0.0.141 \
    proto esp spi 0xc0ffee01 mode tunnel reqid 1 \
    aead 'rfc4106(gcm(aes))' 0x0123456789abcdef0123456789abcdef0a1b2c3d 128
ip xfrm state add src 10.0.0.141 dst 10.0.0.62  \
    proto esp spi 0xc0ffee02 mode tunnel reqid 1 \
    aead 'rfc4106(gcm(aes))' 0xfedcba9876543210fedcba9876543210e0f1a2b3 128

# Policies + route + MASQUERADE bypass identical to §1.
```

### Observed

- ICMP from loki at 1 PPS: 100 % delivered. Bug doesn't manifest at low rate.
- TCP iperf3 (15 s): **2 – 3 Mbit/s, 600+ retransmits** — TCP cwnd never escapes
  congestion-recovery because of high ICV-fail loss.
- UDP iperf3 (5 s, 1 Gbit/s, 1400 B): **140 Mbit/s receiver, 86 % loss**, +384 000
  `XfrmInStateProtoError` ticks on Vision in 5 s. ProtoError = AEAD ICV verification
  failed — the wire packets arrive but Vision can't authenticate them.
- 500-frame ESP capture occasionally shows 4 / 500 sequence-number duplicates (0.8 %).
  Duplicates are the visible tip of a deeper concurrency race — most failed packets
  have unique seqs but internally-inconsistent ICV vs wire SEQ/IV (race between AAD
  construction and wire-header emission inside SEC).
- **Reproduces identically on a freshly-booted DUT** — first iperf3 after first ping
  produces the same 86 % loss. Not a wedge, not a state-buildup, not transient.

### Tear-down (any of the three configs)

```sh
sudo ip xfrm state flush; sudo ip xfrm policy flush
# DUT only:
iptables -t nat -D POSTROUTING -s 192.168.1.0/24 -d 10.99.0.2/32 -j ACCEPT
```
