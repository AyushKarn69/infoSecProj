"""Generate local-only CA and mTLS certificates for the Docker demonstrator."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def write_identity(
    directory: Path, name: str, ca_key, ca_cert, *, server: bool, dns_names: list[str]
) -> None:
    key = ec.generate_private_key(ec.SECP384R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    sans = [x509.DNSName(item) for item in dns_names]
    if name == "control-api":
        sans.extend([x509.DNSName("localhost"), x509.IPAddress(ip_address("127.0.0.1"))])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH] if server else [ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA384())
    )
    (directory / f"{name}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (directory / f"{name}-key.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("infrastructure/dev-certs"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    ca_key = ec.generate_private_key(ec.SECP384R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "RiskShare Local Development CA")])
    now = datetime.now(UTC)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA384())
    )
    (args.output / "ca.pem").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    (args.output / "ca-key.pem").write_bytes(
        ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    write_identity(
        args.output, "control-api", ca_key, ca_cert, server=False, dns_names=["riskshare-control"]
    )
    for node_id in range(1, 6):
        write_identity(
            args.output,
            f"node-{node_id}",
            ca_key,
            ca_cert,
            server=True,
            dns_names=[f"node-{node_id}"],
        )
    print(f"Generated development-only mTLS identities in {args.output.resolve()}")


if __name__ == "__main__":
    main()
