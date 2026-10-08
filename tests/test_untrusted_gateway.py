"""Refusal test: a gateway whose certificate is signed by an unknown CA must be rejected by the terminal."""
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import local_gateway as g

def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PayProof Systems")])

rogue_ca_key = ec.generate_private_key(ec.SECP256R1())
rogue_gw_key = ec.generate_private_key(ec.SECP256R1())
now = datetime.datetime.now(datetime.timezone.utc)
cert = (x509.CertificateBuilder()
        .subject_name(name("PayProof Gateway"))
        .issuer_name(name("PayProof Root CA v1"))
        .public_key(rogue_gw_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(rogue_ca_key, hashes.SHA256()))
der = cert.public_bytes(serialization.Encoding.DER)
assert len(der) <= 512, f"rogue cert too big: {len(der)}"

gw = g.GatewaySimulator("/dev/ttyUSB0", 115200)
gw.cert_der = der
gw.gateway_key = rogue_gw_key
print(f"[TEST] Gateway is now an IMPOSTOR: cert ({len(der)} bytes) uses the real CA's name but an unknown signing key.")
print("[TEST] The terminal must refuse before sending any challenge.")
gw.run()
