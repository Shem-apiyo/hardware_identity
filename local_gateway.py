"""
local_gateway.py
================
Blueprint v2.3 PoC — Simulated Gateway (Laptop over UART)

Responsibilities:
  1. Send gateway_cert.der + Gateway_Nonce (32 bytes) to terminal
  2. Receive Terminal_Challenge (32 bytes)
  3. Sign Terminal_Challenge with Gateway private key
  4. Send signature back to terminal
  5. Receive Sealed Transaction Record
  6. Parse outer envelope (length-prefix + schema_id routing)
  7. Verify terminal ECDSA signature
  8. Print transaction result

Protocol state machine (Blueprint v2.3 Section 2):
  IDLE → CERT_SENT → CHALLENGE_RECEIVED → SIG_SENT → RECORD_RECEIVED → VERIFY

Timeouts (Blueprint v2.3 Section 2 — transport-specific):
  UART 115200 baud: T_timeout = 50ms per receive operation
  Each state has its own timeout. Any timeout → DISCARD protocol.

DISCARD protocol (on any timeout or abort):
  1. Zeroize all partial buffers
  2. Reset state machine to IDLE
  3. Increment fail_counter
  4. If fail_counter >= 3: enforce 60-second backoff (SLEEP)
  5. fail_counter resets only on TRANSACTION_VALID

Schema 0x01 (PayProof) — 5 bytes fixed:
  [0:3] amount        uint32 big-endian  (e.g. 5000 = KES 50.00)
  [4]   currency_code uint8              (0x01 = KES)

Usage:
  python local_gateway.py [--port /dev/ttyACM0 ] [--baud 115200]

Dependencies:
  pip install cryptography pyserial
"""

import os
import sys
import time
import struct
import argparse
from pathlib import Path

import serial

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509


# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

ARTIFACTS_DIR     = Path("poc_artifacts")
GATEWAY_CERT_PATH = ARTIFACTS_DIR / "gateway_cert.der"
GATEWAY_KEY_PATH  = ARTIFACTS_DIR / "gateway_key.pem"
ROOT_CERT_PATH    = ARTIFACTS_DIR / "root_ca_cert.pem"

DEFAULT_PORT      = "/dev/ttyACM0"
DEFAULT_BAUD      = 115200

# Blueprint v2.3 — UART transport timeout
UART_TIMEOUT_S    = 2.0   # 50ms per receive operation

# Framing constants shared with terminal firmware
NONCE_LEN         = 32     # Gateway_Nonce length in bytes
CHALLENGE_LEN     = 32     # Terminal_Challenge length in bytes
MAC_LEN           = 6      # terminal_id (MAC address)
COUNTER_LEN       = 4      # eFuse monotonic counter
TIMESTAMP_LEN     = 8      # RTC timestamp (untrusted, audit only)
SIG_LEN           = 64     # ECDSA P-256 raw signature (r||s, 32+32)

# Schema 0x01 PayProof fixed payload
SCHEMA_PAYPROOF   = 0x01
SCHEMA_PAYPROOF_LEN = 5    # uint32 amount + uint8 currency_code

# Rate limiting (Blueprint v2.3 Section 5)
FAIL_THRESHOLD    = 3
BACKOFF_SECONDS   = 60


# ─────────────────────────────────────────────────────────────────────────────
# State machine states
# ─────────────────────────────────────────────────────────────────────────────

class State:
    IDLE               = "IDLE"
    CERT_SENT          = "CERT_SENT"
    CHALLENGE_RECEIVED = "CHALLENGE_RECEIVED"
    SIG_SENT           = "SIG_SENT"
    RECORD_RECEIVED    = "RECORD_RECEIVED"
    SLEEP              = "SLEEP"


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def zeroize(buf: bytearray) -> None:
    """Overwrite buffer contents with zeros."""
    for i in range(len(buf)):
        buf[i] = 0


def recv_exact(port: serial.Serial, n: int, timeout_s: float) -> bytes | None:
    """
    Read exactly n bytes from serial port within timeout_s seconds.
    Returns bytes on success, None on timeout or short read.
    Blueprint v2.3: any partial receive triggers DISCARD protocol.
    """
    deadline = time.monotonic() + timeout_s
    buf = b""
    while len(buf) < n:
        if time.monotonic() > deadline:
            return None
        remaining = n - len(buf)
        chunk = port.read(remaining)
        buf += chunk
        if not chunk:
            time.sleep(0.001)
    return buf if len(buf) == n else None


def send_length_prefixed(port: serial.Serial, data: bytes) -> None:
    """
    Send data prefixed with 2-byte big-endian length.
    Terminal firmware reads length first, then exact bytes.
    """
    length = struct.pack(">H", len(data))
    port.write(length + data)
    port.flush()


def recv_length_prefixed(port: serial.Serial, timeout_s: float) -> bytes | None:
    """
    Receive 2-byte big-endian length then exactly that many bytes.
    Returns None on any timeout or framing error.
    """
    raw_len = recv_exact(port, 2, timeout_s)
    if raw_len is None:
        return None
    n = struct.unpack(">H", raw_len)[0]
    if n == 0 or n > 4096:
        return None
    return recv_exact(port, n, timeout_s)


def parse_transaction_record(record: bytes) -> dict | None:
    """
    Parse the sealed transaction record per Blueprint v2.3 Section 3.

    OUTER ENVELOPE layout (all multi-byte fields big-endian):
      terminal_id      6 bytes
      gateway_nonce    32 bytes
      data_length      2 bytes
      transaction_data N bytes
      efuse_counter    4 bytes
      timestamp        8 bytes

    TRANSACTION_DATA layout:
      schema_id        1 byte
      schema_payload   N-1 bytes

    SIGNATURE (appended after envelope):
      64 bytes raw ECDSA P-256 (r||s)
    """
    MIN_ENVELOPE = MAC_LEN + NONCE_LEN + 2  # at minimum before data_length
    if len(record) < MIN_ENVELOPE + SIG_LEN:
        return None

    offset = 0
    terminal_id   = record[offset:offset + MAC_LEN];     offset += MAC_LEN
    gateway_nonce = record[offset:offset + NONCE_LEN];   offset += NONCE_LEN
    data_length   = struct.unpack_from(">H", record, offset)[0]; offset += 2

    if offset + data_length + COUNTER_LEN + TIMESTAMP_LEN + SIG_LEN > len(record):
        return None

    transaction_data = record[offset:offset + data_length]; offset += data_length
    efuse_counter    = struct.unpack_from(">I", record, offset)[0]; offset += COUNTER_LEN
    timestamp        = struct.unpack_from(">Q", record, offset)[0]; offset += TIMESTAMP_LEN

    # Everything up to here is the signed envelope
    envelope  = record[:offset]
    signature = record[offset:offset + SIG_LEN]

    if len(signature) != SIG_LEN:
        return None

    # Parse transaction_data
    if len(transaction_data) < 1:
        return None

    schema_id      = transaction_data[0]
    schema_payload = transaction_data[1:]

    return {
        "terminal_id":      terminal_id,
        "gateway_nonce":    gateway_nonce,
        "transaction_data": transaction_data,
        "schema_id":        schema_id,
        "schema_payload":   schema_payload,
        "efuse_counter":    efuse_counter,
        "timestamp":        timestamp,
        "envelope":         envelope,
        "signature":        signature,
    }


def decode_payproof(schema_payload: bytes) -> dict | None:
    """Decode Schema 0x01 PayProof fixed 5-byte payload."""
    if len(schema_payload) != SCHEMA_PAYPROOF_LEN - 1:
        # schema_payload excludes the schema_id byte already
        # Full schema payload = 5 bytes: 4 (amount) + 1 (currency)
        # After stripping schema_id: 4 bytes
        return None
    if len(schema_payload) != 4:
        return None
    amount        = struct.unpack_from(">I", schema_payload, 0)[0]
    currency_code = 0  # currency is the 5th byte of full transaction_data
    return {"amount": amount, "currency_code": currency_code}


def decode_payproof_full(transaction_data: bytes) -> dict | None:
    """
    Decode Schema 0x01 from full transaction_data field.
    transaction_data[0]   = schema_id  (0x01)
    transaction_data[1:5] = amount     uint32 big-endian
    transaction_data[5]   = currency   uint8
    Total: 6 bytes (1 schema_id + 5 schema_payload)
    """
    if len(transaction_data) != 1 + SCHEMA_PAYPROOF_LEN:
        return None
    schema_id     = transaction_data[0]
    amount        = struct.unpack_from(">I", transaction_data, 1)[0]
    currency_code = transaction_data[5]
    return {
        "schema_id":     schema_id,
        "amount":        amount,
        "currency_code": currency_code,
    }


CURRENCY_NAMES = {
    0x01: "KES",
    0x02: "USD",
    0x03: "EUR",
}


def verify_terminal_signature(
    record: dict,
    terminal_pubkey_der: bytes
) -> bool:
    """
    Verify the terminal ECDSA P-256 signature over the outer envelope.
    Signature is raw 64-byte r||s format.
    """
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature, encode_dss_signature
    )
    import math

    try:
        pub_key = serialization.load_der_public_key(terminal_pubkey_der)

        # Convert raw r||s (64 bytes) to DER signature for cryptography library
        r = int.from_bytes(record["signature"][:32], "big")
        s = int.from_bytes(record["signature"][32:], "big")
        der_sig = encode_dss_signature(r, s)

        pub_key.verify(der_sig, record["envelope"], ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Gateway simulation
# ─────────────────────────────────────────────────────────────────────────────

READY_MARKER = b"\xa5PPRDY\x5a\x0a"


class GatewaySimulator:

    def __init__(self, port: str, baud: int):
        self.port_name   = port
        self.baud        = baud
        self.state       = State.IDLE
        self.fail_counter = 0

        # Load artifacts
        print(f"[GATEWAY] Loading artifacts from {ARTIFACTS_DIR.resolve()}")

        if not GATEWAY_CERT_PATH.exists():
            raise FileNotFoundError(
                f"gateway_cert.der not found. Run backend_ca.py first."
            )
        if not GATEWAY_KEY_PATH.exists():
            raise FileNotFoundError(
                f"gateway_key.pem not found. Run backend_ca.py first."
            )

        self.cert_der = GATEWAY_CERT_PATH.read_bytes()
        print(f"[GATEWAY] Certificate loaded: {len(self.cert_der)} bytes")

        self.gateway_key = serialization.load_pem_private_key(
            GATEWAY_KEY_PATH.read_bytes(), password=None
        )
        print(f"[GATEWAY] Gateway private key loaded.")
        print()

        # In PoC: terminal public key hardcoded from one-time extraction (debug export).
        # In production: loaded from terminal registry database.
        terminal_pubkey_raw = bytes.fromhex(
            "04287423fb2c398306715a5f7ee212dfa3115d7d96ccf91955246e36957b66074baeaf9d1e040638ca3f9738b4a54fb227995fa135b227f3c33c25fdab24fde8c5"
        )
        terminal_pub_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), terminal_pubkey_raw
        )
        self.terminal_pubkey_der = terminal_pub_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # Per-terminal last-accepted counter store (persisted across gateway restarts)
        self.counter_store_path = Path(__file__).parent / "poc_artifacts" / "counter_store.json"
        self.last_counters = {}
        try:
            if self.counter_store_path.exists():
                import json
                self.last_counters = json.loads(self.counter_store_path.read_text())
        except Exception as e:
            print(f"[WARN]    Could not load counter store: {e}")

    def _save_counters(self):
        import json
        try:
            self.counter_store_path.write_text(json.dumps(self.last_counters))
        except Exception as e:
            print(f"[WARN]    Could not save counter store: {e}")

    def discard(self, reason: str, partial_bufs: list[bytearray] = None) -> None:
        """
        Blueprint v2.3 DISCARD protocol:
        1. Zeroize all partial buffers
        2. Reset state to IDLE
        3. Increment fail_counter
        4. Enforce backoff if threshold reached
        """
        print(f"[DISCARD] Reason: {reason}")

        if partial_bufs:
            for buf in partial_bufs:
                zeroize(buf)
            print(f"[DISCARD] Zeroized {len(partial_bufs)} partial buffer(s).")

        self.state = State.IDLE
        self.fail_counter += 1
        print(f"[DISCARD] fail_counter = {self.fail_counter}/{FAIL_THRESHOLD}")

        if self.fail_counter >= FAIL_THRESHOLD:
            print(f"[SLEEP]   Fail threshold reached. Enforcing {BACKOFF_SECONDS}s backoff.")
            print(f"[SLEEP]   Backoff resets only on TRANSACTION_VALID.")
            self.state = State.SLEEP
            time.sleep(BACKOFF_SECONDS)
            self.state = State.IDLE
            print(f"[SLEEP]   Backoff complete. Returning to IDLE.")

    def run_handshake(self, port: serial.Serial) -> bool:
        """
        Execute one full handshake + transaction cycle.
        Returns True on TRANSACTION_VALID, False on any failure.
        """
        # ── Step 1: Send certificate + Gateway_Nonce ─────────────────────────
        gateway_nonce = bytearray(os.urandom(NONCE_LEN))
        print(f"[STATE]   IDLE → CERT_SENT")
        print(f"[TX]      Sending certificate ({len(self.cert_der)} bytes) + nonce (32 bytes)")

        # Send cert length-prefixed, then nonce raw
        send_length_prefixed(port, self.cert_der)
        port.write(bytes(gateway_nonce))
        port.flush()
        self.state = State.CERT_SENT

        # ── Step 2: Receive Terminal_Challenge ───────────────────────────────
        print(f"[RX]      Waiting for Terminal_Challenge (32 bytes, timeout={UART_TIMEOUT_S*1000:.0f}ms)...")
        challenge_buf = bytearray(CHALLENGE_LEN)
        raw_challenge = recv_exact(port, CHALLENGE_LEN, UART_TIMEOUT_S)

        if raw_challenge is None:
            self.discard("Timeout waiting for Terminal_Challenge", [gateway_nonce, challenge_buf])
            return False

        challenge_buf[:] = raw_challenge
        self.state = State.CHALLENGE_RECEIVED
        print(f"[STATE]   CERT_SENT → CHALLENGE_RECEIVED")
        print(f"[RX]      Terminal_Challenge: {raw_challenge.hex()[:16]}...")

        # ── Step 3: Sign Terminal_Challenge with Gateway private key ─────────
        print(f"[SIGN]    Signing Terminal_Challenge with Gateway private key...")
        try:
            from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
            der_sig = self.gateway_key.sign(bytes(challenge_buf), ec.ECDSA(hashes.SHA256()))
            # Convert DER signature to raw r||s (64 bytes) for terminal
            r, s = decode_dss_signature(der_sig)
            raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        except Exception as e:
            self.discard(f"Signing failed: {e}", [gateway_nonce, challenge_buf])
            return False

        # ── Step 4: Send signature ───────────────────────────────────────────
        send_length_prefixed(port, der_sig)
        self.state = State.SIG_SENT
        print(f"[STATE]   CHALLENGE_RECEIVED → SIG_SENT")
        print(f"[TX]      Sent signature ({len(der_sig)} bytes): {der_sig.hex()[:16]}...")

        # ── Step 5: Receive Sealed Transaction Record ────────────────────────
        # Longer timeout here — terminal does HKDF + ECDSA sign
        record_timeout = 5.0  # 1000ms for crypto operations
        print(f"[RX]      Waiting for Sealed Transaction Record (timeout={record_timeout*1000:.0f}ms)...")
        raw_record = recv_length_prefixed(port, record_timeout)

        if raw_record is None:
            self.discard("Timeout waiting for Sealed Transaction Record",
                         [gateway_nonce, challenge_buf])
            return False

        self.state = State.RECORD_RECEIVED
        print(f"[STATE]   SIG_SENT → RECORD_RECEIVED")
        print(f"[RX]      Record received: {len(raw_record)} bytes")

        # ── Step 6: Parse record ─────────────────────────────────────────────
        parsed = parse_transaction_record(raw_record)
        if parsed is None:
            self.discard("Failed to parse transaction record",
                         [gateway_nonce, challenge_buf])
            return False

        # ── Step 7: Verify Gateway_Nonce matches ─────────────────────────────
        if parsed["gateway_nonce"] != bytes(gateway_nonce):
            self.discard("Gateway_Nonce mismatch — possible replay or substitution",
                         [gateway_nonce, challenge_buf])
            return False

        print(f"[CHECK]   Gateway_Nonce match: OK")

        # ── Step 8: Verify eFuse counter monotonicity ────────────────────────
        # In production: compare against stored last_counter for this terminal_id
        # For PoC: just print and accept (no persistent registry yet)
        terminal_id_hex = parsed["terminal_id"].hex(":")
        print(f"[CHECK]   Terminal ID:    {terminal_id_hex}")
        print(f"[CHECK]   eFuse Counter:  {parsed['efuse_counter']}")
        print(f"[CHECK]   Timestamp:      {parsed['timestamp']} (untrusted, audit only)")

        # ── Step 9: Parse schema ─────────────────────────────────────────────
        schema_id = parsed["schema_id"]
        # ── Replay protection: per-terminal counter monotonicity (schema 0x01) ──
        if schema_id == SCHEMA_PAYPROOF:
            incoming = parsed["efuse_counter"]
            last = self.last_counters.get(terminal_id_hex, 0)
            if incoming <= last:
                self.discard(f"Replay detected: counter {incoming} <= last accepted {last} for {terminal_id_hex}", [gateway_nonce, challenge_buf])
                return False
            print(f"[CHECK]   Counter monotonic: {incoming} > {last} OK")
        print(f"[SCHEMA]  schema_id = 0x{schema_id:02x}", end="")

        if schema_id == SCHEMA_PAYPROOF:
            print(" (PayProof KES payment)")
            decoded = decode_payproof_full(parsed["transaction_data"])
            if decoded is None:
                self.discard("PayProof schema payload malformed",
                             [gateway_nonce, challenge_buf])
                return False
            amount        = decoded["amount"]
            currency_code = decoded["currency_code"]
            currency_name = CURRENCY_NAMES.get(currency_code, f"0x{currency_code:02x}")
            amount_display = amount / 100.0
        else:
            print(f" (Unknown schema — routing to backend)")
            amount_display = 0
            currency_name  = "UNKNOWN"

        # ── Step 10: Verify terminal signature ───────────────────────────────
        # PoC note: terminal_pubkey_der would come from registry lookup by terminal_id
        # For now: attempt verification if pubkey is available, skip with warning if not
        if self.terminal_pubkey_der is not None:
            sig_valid = verify_terminal_signature(parsed, self.terminal_pubkey_der)
            if not sig_valid:
                self.discard("Terminal ECDSA signature verification FAILED",
                             [gateway_nonce, challenge_buf])
                return False
            print(f"[VERIFY]  Terminal signature: VALID")
            # Save the counter only after the signature is proven genuine
            if schema_id == SCHEMA_PAYPROOF:
                self.last_counters[terminal_id_hex] = parsed["efuse_counter"]
                self._save_counters()
        else:
            print(f"[VERIFY]  Terminal signature: SKIPPED (terminal pubkey not in registry yet)")
            print(f"[VERIFY]  In production: registry lookup by terminal_id required here.")

        # ── Step 11: Zeroize working buffers ─────────────────────────────────
        zeroize(gateway_nonce)
        zeroize(challenge_buf)

        # ── TRANSACTION VALID ─────────────────────────────────────────────────
        self.fail_counter = 0  # Reset on success — Blueprint v2.3 Section 5
        print()
        print("=" * 56)
        if schema_id == SCHEMA_PAYPROOF:
            print(f"  [TRANSACTION VALID]")
            print(f"  Amount:   {amount_display:.2f} {currency_name}")
            print(f"  Terminal: {terminal_id_hex}")
            print(f"  Counter:  {parsed['efuse_counter']}")
        else:
            print(f"  [TRANSACTION VALID] schema=0x{schema_id:02x} — forwarded to backend")
        print("=" * 56)
        print()
        self.state = State.IDLE
        return True

    def wait_for_ready(self, port: serial.Serial) -> None:
        """Block until the terminal READY marker arrives. All other bytes are ignored."""
        print("[GATEWAY] Waiting for terminal READY marker...")
        port.reset_input_buffer()
        window = b""
        while True:
            b = port.read(1)
            if not b:
                continue
            window = (window + b)[-len(READY_MARKER):]
            if window == READY_MARKER:
                time.sleep(0.05)
                port.reset_input_buffer()
                print("[GATEWAY] Terminal READY.")
                return

    def run(self) -> None:
        """Main gateway loop — listens for terminal initiations."""
        print(f"[GATEWAY] Opening serial port {self.port_name} at {self.baud} baud...")
        try:
            port = serial.Serial(
                self.port_name,
                baudrate=self.baud,
                timeout=UART_TIMEOUT_S,
            )
        except serial.SerialException as e:
            print(f"[ERROR]   Cannot open {self.port_name}: {e}")
            sys.exit(1)

        print(f"[GATEWAY] Listening. Waiting for terminal to initiate handshake.")
        print(f"[GATEWAY] Press Ctrl+C to stop.")
        print()

        try:
            while True:
                if self.state == State.IDLE:
                    self.wait_for_ready(port)
                    print(f"[GATEWAY] Sending initiation signal to terminal.")
                    port.write(b'\x01')
                    port.flush()
                    self.run_handshake(port)

        except KeyboardInterrupt:
            print("\n[GATEWAY] Stopped by user.")
        finally:
            port.close()


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="PayProof Gateway Simulator — Blueprint v2.3 PoC"
    )
    parser.add_argument("--port", default=DEFAULT_PORT,
                        help=f"Serial port (default: {DEFAULT_PORT})")
    parser.add_argument("--baud", type=int, default=DEFAULT_BAUD,
                        help=f"Baud rate (default: {DEFAULT_BAUD})")
    args = parser.parse_args()

    print("=" * 56)
    print("PayProof Gateway Simulator — Blueprint v2.3 PoC")
    print("=" * 56)

    gw = GatewaySimulator(args.port, args.baud)
    gw.run()


if __name__ == "__main__":
    main()


