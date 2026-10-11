# Hardware-rooted device identity on ESP32-S3

A proof of concept. An ESP32-S3 derives a signing key from an HMAC key held in eFuse, and uses it to prove its identity to a gateway over UART. PayProof (a 50 KES test payment record) is the example payload.

**Status:** development build on a single development board. Secure Boot and Flash Encryption are not enabled. Read "Known limitations" before relying on anything here.

## What it does

1. The gateway proves itself to the terminal with a certificate signed by a Root CA the terminal trusts.
2. The terminal derives a signing key from eFuse `KEY4` and signs a record.
3. The gateway checks the record against a public key it enrolled earlier.

Nothing that identifies the device is stored in flash. The identity is rebuilt from `KEY4` on every handshake.

## Handshake

| Step | Sender | What happens |
|---|---|---|
| 1 | Terminal | Sends an 8-byte READY marker while idle |
| 2 | Gateway | Sends its certificate and a 32-byte nonce |
| 3 | Terminal | Verifies the certificate against the embedded Root CA certificate |
| 4 | Terminal | Sends a 32-byte random challenge |
| 5 | Gateway | Signs the challenge with its private key |
| 6 | Terminal | Verifies that signature using the certificate's public key |
| 7 | Terminal | Computes `HMAC(KEY4, fixed message)` in hardware and imports the 32-byte result as an ECDSA P-256 private key |
| 8 | Terminal | Builds the record, signs it, destroys the key, sends the record |
| 9 | Gateway | Checks nonce, counter and signature, in that order, then saves the counter |

Record layout (122 bytes): terminal MAC (6), gateway nonce (32), data length (2), schema ID (1), amount (4), currency (1), counter (4), timestamp (8), ECDSA signature (64).

## What has been demonstrated

All logs are in `evidence/` and were produced in October 2026 with the code in this repository.

| Claim | Evidence |
|---|---|
| A genuine terminal completes the handshake and its record is accepted | `00_valid_handshake.log` |
| The identity comes from `KEY4`, not from flash: the public key committed in `7f2a648` still verifies signatures after the board was fully reflashed | `00_valid_handshake.log` and the unchanged key in `local_gateway.py` |
| A record signed by a key other than the enrolled one is rejected, and the counter store is not changed | `01_wrong_key_rejected.log` |
| A record whose counter is at or below the last accepted one is rejected | `02_stale_counter_rejected.log` |
| A gateway whose certificate is not signed by the trusted CA is rejected before the terminal sends a challenge or uses `KEY4` | `03_untrusted_gateway_terminal_side.log`, `03_untrusted_gateway_gateway_side.log` |

## Known limitations

These are true of the code as it stands.

- **The counter is stored in NVS, not eFuse.** Anyone who can rewrite flash can roll it back. Logs `01` and `02` predate a label fix and call it "eFuse Counter"; the value was always the NVS counter. A counter that burns one eFuse bit per transaction would use up a 256-bit block after 256 transactions, so it is not practical here.
- **The derived signing key is in application RAM while signing.** `KEY4` never leaves the hardware. The key derived from it does, briefly.
- **Secure Boot and Flash Encryption are off.** Anyone with physical access can replace the firmware, including the embedded Root CA certificate.
- **The terminal gets no verdict from the gateway.** It logs `RECORD_SENT` and spends a counter value whether or not the gateway accepts the record.
- **One terminal public key is hardcoded in the gateway.** There is no device registry and no enrollment tool in this repository. The key was read from the board once, with code that is not included here.
- **UART only.** No WiFi, no TCP, no TLS.
- **The record format is custom.** It is not COSE.
- **The timestamp is always zero** and the payload is a fixed test amount.

## Not tested on this build

- A record altered in transit
- A captured record replayed into a new session
- Fuzzing of the gateway or terminal parsers
- Flash dump, fault injection or any other physical attack

## Roadmap

- Rollback protection: a slow eFuse epoch combined with the NVS counter
- Signed acknowledgement from gateway to terminal
- Device registry and an enrollment procedure
- WiFi/TCP transport with TLS
- COSE_Sign1 record format
- Secure Boot v2 and Flash Encryption on a production unit

## Hardware and tools

- ESP32-S3 with an HMAC key provisioned in eFuse `KEY4` (purpose `HMAC_UP`)
- USB-UART bridge (CP210x used here)
- ESP-IDF v6.0.x (built with v6.0.3)
- Python 3 with `pyserial` and `cryptography`

Provisioning `KEY4` is a one-way eFuse operation. Follow Espressif's HMAC peripheral documentation and do not improvise it.

| Bridge | ESP32-S3 |
|---|---|
| TX | GPIO44 (RX) |
| RX | GPIO43 (TX) |
| GND | GND |

Logs go to the board's USB Serial/JTAG port. UART0 carries only the protocol.

## Build and run

**1. Create your own CA and gateway certificate.**

    python3 backend_ca.py

**2. Embed your Root CA certificate in the firmware.** The `main/root_ca_cert.h` in this repository belongs to the author's CA and will not match yours.

    openssl x509 -in poc_artifacts/root_ca_cert.pem -outform DER -out poc_artifacts/root_ca_cert.der
    {
      echo '#pragma once'
      echo '#include <stdint.h>'
      echo '#include <stddef.h>'
      echo 'static const uint8_t ROOT_CA_CERT[] = {'
      xxd -i < poc_artifacts/root_ca_cert.der
      echo '};'
      echo 'static const size_t ROOT_CA_CERT_len = sizeof(ROOT_CA_CERT);'
    } > main/root_ca_cert.h

**3. Build, flash and watch the terminal.**

    idf.py -p /dev/ttyACM0 build flash monitor

**4. In a second shell, start the gateway on the bridge port.**

    python3 local_gateway.py --port /dev/ttyUSB0 --baud 115200

To use your own board you must also replace the terminal public key hardcoded in `local_gateway.py`. See "Known limitations".

## Reproducing the refusal tests

- **Wrong key:** start the gateway with `terminal_pubkey_der` replaced by a freshly generated P-256 public key. Every record must fail signature verification and `poc_artifacts/counter_store.json` must not change.
- **Stale counter:** set the stored counter in `poc_artifacts/counter_store.json` above the terminal's current counter, then run the gateway normally.
- **Untrusted gateway:** `PYTHONPATH=. python3 tests/test_untrusted_gateway.py`, with the terminal monitor open. The refusal is visible in the terminal log.

## Repository layout

| Path | Purpose |
|---|---|
| `main/terminal_firmware.c` | Terminal firmware |
| `main/root_ca_cert.h` | Embedded Root CA certificate (regenerate for your CA) |
| `local_gateway.py` | Gateway simulator |
| `backend_ca.py` | Generates the CA, gateway key and certificate |
| `tests/` | Refusal tests |
| `evidence/` | Logs backing the claims above |
| `poc_artifacts/` | Private keys and certificates. Git-ignored. Never commit this folder. |
