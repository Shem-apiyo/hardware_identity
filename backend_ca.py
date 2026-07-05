import os
import datetime
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

OUTPUT_DIR = Path("poc_artifacts")
CERT_VALID_DAYS = 365
ROOT_CN   = "PayProof Root CA v1"
ROOT_ORG  = "PayProof Systems"
GW_CN     = "PayProof Gateway POC-001"
GW_ORG    = "PayProof Systems"

def generate_ec_keypair():
    return ec.generate_private_key(ec.SECP256R1())

def pubkey_to_c_array(public_key, var_name):
    der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    lines = []
    lines.append("/* Root CA Public Key -- SubjectPublicKeyInfo DER format */")
    lines.append(f"static const uint8_t {var_name}[] = {{")
    raw = list(der_bytes)
    for i in range(0, len(raw), 8):
        chunk = raw[i:i+8]
        chunk_str = ", ".join(f"0x{b:02x}" for b in chunk)
        lines.append(f"    {chunk_str},")
    lines.append("};")
    lines.append(f"static const size_t {var_name}_len = {len(der_bytes)};")
    return "\n".join(lines)

def build_x509_cert(subject_key, subject_cn, subject_org,
                    issuer_key, issuer_cn, issuer_org,
                    is_ca=False, valid_days=CERT_VALID_DAYS):
    subject_pubkey = subject_key.public_key()
    now = datetime.datetime.now(datetime.timezone.utc)
    subject_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_org),
    ])
    issuer_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer_org),
    ])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer_name)
        .public_key(subject_pubkey)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=0 if is_ca else None),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(subject_pubkey),
            critical=False,
        )
    )
    if not is_ca:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    return builder.sign(issuer_key, hashes.SHA256())

def main():
    print("=" * 64)
    print("PayProof Root CA Key Generation Ceremony")
    print("Blueprint v2.3 PoC")
    print("=" * 64)
    OUTPUT_DIR.mkdir(exist_ok=True)
    print(f"[+] Output directory: {OUTPUT_DIR.resolve()}")

    print("[1/5] Generating Root CA keypair (ECDSA P-256)...")
    root_key = generate_ec_keypair()

    print("[2/5] Self-signing Root CA certificate...")
    root_cert = build_x509_cert(root_key, ROOT_CN, ROOT_ORG,
                                 root_key, ROOT_CN, ROOT_ORG, is_ca=True)

    print("[3/5] Generating Gateway keypair (ECDSA P-256)...")
    gateway_key = generate_ec_keypair()

    print("[4/5] Signing Gateway certificate with Root CA...")
    gateway_cert = build_x509_cert(gateway_key, GW_CN, GW_ORG,
                                    root_key, ROOT_CN, ROOT_ORG, is_ca=False)

    print("[5/5] Writing artifacts...")

    root_key_path = OUTPUT_DIR / "root_ca_key.pem"
    root_key_path.write_bytes(root_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    print(f"      [!] Root CA private key -> {root_key_path}")

    (OUTPUT_DIR / "root_ca_cert.pem").write_bytes(
        root_cert.public_bytes(serialization.Encoding.PEM))
    print(f"      [+] Root CA certificate -> poc_artifacts/root_ca_cert.pem")

    gw_key_path = OUTPUT_DIR / "gateway_key.pem"
    gw_key_path.write_bytes(gateway_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    print(f"      [+] Gateway private key  -> {gw_key_path}")

    gw_cert_der_bytes = gateway_cert.public_bytes(serialization.Encoding.DER)
    (OUTPUT_DIR / "gateway_cert.der").write_bytes(gw_cert_der_bytes)
    print(f"      [+] Gateway certificate  -> poc_artifacts/gateway_cert.der ({len(gw_cert_der_bytes)} bytes)")

    c_header = "\n".join([
        "#pragma once",
        "#include <stdint.h>",
        "#include <stddef.h>",
        "/* root_pubkey.h -- auto-generated by backend_ca.py */",
        "",
        pubkey_to_c_array(root_key.public_key(), "ROOT_CA_PUBKEY"),
    ])
    (OUTPUT_DIR / "root_pubkey.h").write_text(c_header)
    print(f"      [+] Root public key C header -> poc_artifacts/root_pubkey.h")

    print()
    print("=" * 64)
    print("Verification:")
    try:
        root_cert.public_key().verify(
            gateway_cert.signature,
            gateway_cert.tbs_certificate_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        print("  [PASS] Gateway certificate verified against Root CA.")
    except Exception as e:
        print(f"  [FAIL] {e}")
        return

    print(f"  gateway_cert.der : {len(gw_cert_der_bytes)} bytes")
    print("=" * 64)

if __name__ == "__main__":
    main()
