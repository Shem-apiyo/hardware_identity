# Hardware-Rooted Device Identity — a service-agnostic trust substrate (Reference Implementation)

**PayProof** is a device-identity and mutual-authentication substrate for constrained
microcontrollers, where the device's private key is **derived on demand from a
read-protected eFuse and never stored at rest** — no secure element, no assumption of
network access. It is service-agnostic: payment is one telemetry it carries, not its
purpose.

This repository is a **reference implementation**, not a flashable project. It contains
the CA/certificate tooling, a simulated gateway that runs the full handshake state
machine, and the terminal-side firmware source that shows the on-device logic.

---

## The problem

Give each device a cryptographic identity that can't be cloned, extracted, or
impersonated — on an ESP32-S3 with no secure element, over a transport with no TLS,
where a replayed message must never be accepted twice. The identity and replay
guarantees are general: they hold for any authenticated telemetry a device emits.
Payment is one such telemetry (a replayed record double-counts a transaction), not
the design's purpose — the substrate is service-agnostic and routes by `schema_id`.

## The decision (and what was rejected)

**Root of trust: eFuse HMAC, not stored keys.** The device keypair is derived as a pure
function of a secret burned into a read-protected eFuse block (`HMAC_UP`, R/-) via the
PSA crypto API. The private key is reconstructed in hardware on demand and never
persisted.
*Rejected:* storing a provisioned private key in encrypted flash — it creates a
key-at-rest recoverable by a flash dump plus one broken firmware assumption.

**Entropy: eFuse, not SRAM PUF.** An SRAM PUF was characterised first (raw entropy
~1,487 bits/device; ~464 bits after BCH(255,119,20)×8 ECC leakage under thermal stress)
and **abandoned** — the ESP32-S3 v0.2 die zeroes SRAM on cold power-on at the hardware
level, below the firmware, overriding the `.noinit` region the scheme depends on.
*Rejected:* a floating ADC pin as entropy source — multiplexer ghosting, EMI-antenna
effects, entropy collapse, and trivial tamper injection.

**Protocol: fail closed.** Dual-nonce mutual auth (the terminal issues the challenge),
length-prefixed packed-binary records with a `schema_id` routing byte, and a DISCARD
protocol with a hard 50 ms UART deadline. On any timeout or malformed/unverifiable
input: zeroize buffers, reset to IDLE, increment fail counter, 60 s backoff after 3
failures.
*Rejected:* a RAM-only replay counter with retry-on-timeout — RAM counters reset on
power loss (a free replay window) and generous retries turn a failed verification into a
DoS amplifier.

---

## Trust hierarchy

```
Root CA  →  Backend        →  Gateway            →  Terminal
(air-gap)   (registry/CRL)    (x.509 cert on MCU)   (keypair derived from silicon)
 M-of-N                       ECDSA P-256           eFuse HMAC + PSA derivation
```

## What's in here

| File | Role | Runs on |
|------|------|---------|
| `backend_ca.py` | Generates Root CA + Gateway EC (P-256) keypairs and X.509 DER certs; emits the Root pubkey as a C array | Host (Python) |
| `local_gateway.py` | Simulated gateway: full handshake state machine + DISCARD protocol over UART | Host (Python, laptop) |
| `terminal_firmware.c` | Terminal-side firmware logic: eFuse-derived identity, challenge generation, sealed-record construction | ESP32-S3 (excerpt) |
| `root_pubkey.h` | Root CA public key, DER, as a C header | ESP32-S3 |

## What's deliberately not here

- **Not a buildable ESP-IDF project.** `terminal_firmware.c` is the core logic excerpt;
  the full IDF project (CMake, partitions, `sdkconfig`) is not included.
- **No key material.** All `.pem` artifacts are generated at runtime into a gitignored
  directory and never committed.

## Handshake

```
IDLE → CERT_SENT → CHALLENGE_RECEIVED → SIG_SENT → RECORD_RECEIVED → VERIFY
```

Gateway sends cert + 32-byte nonce; terminal replies with a 32-byte challenge; gateway
signs it; terminal verifies, then returns a sealed transaction record; gateway parses the
length-prefixed envelope, routes on `schema_id`, and verifies the terminal's ECDSA
signature.

## Service routing (`schema_id`)

The sealed record carries a `schema_id` byte so the same identity and replay machinery
serves many telemetries, not one. The transport, auth, and DISCARD path are identical
regardless of payload — payment is just one registered schema:

- `0x00–0xBF` — Standard schemas (e.g. a payment record: `amount` u32 BE + `currency` u8)
- `0xC0–0xFE` — Tenant/service-specific schemas
- `0xFF` — Escape (extended/experimental)

Adding a new telemetry means registering a schema, not changing the trust core.

```bash
pip install cryptography pyserial
python backend_ca.py                       # generates CA, gateway cert, root_pubkey.h
python local_gateway.py --port /dev/ttyACM0 --baud 115200
```

## Known limitations (PoC)

- Gateway artifact keys are stored unencrypted (`password=None`) — a PoC convenience.
  The production path seals identity in eFuse; artifact keys would follow suit.
- The gateway here is a laptop simulation of the on-MCU gateway role, for protocol
  development over UART.
- Secure Boot V2 (RSA-3072) was validated end-to-end in a virtual-eFuse dry run; the
  physical burn is deliberately deferred (irreversible, single working board).

## Status

Protocol and identity model implemented and exercised over UART. Handshake reaches
gateway-signature transmission; end-to-end sealed-record verification is under active
debugging.
