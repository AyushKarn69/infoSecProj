import subprocess
import sys
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID


def test_development_cert_generator_creates_ca_and_mtls_identities(tmp_path: Path) -> None:
    script = Path(__file__).resolve().parents[2] / "scripts" / "generate_dev_certs.py"
    subprocess.run(
        [sys.executable, str(script), "--output", str(tmp_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    ca = x509.load_pem_x509_certificate((tmp_path / "ca.pem").read_bytes())
    control = x509.load_pem_x509_certificate((tmp_path / "control-api.pem").read_bytes())
    node = x509.load_pem_x509_certificate((tmp_path / "node-1.pem").read_bytes())
    control.verify_directly_issued_by(ca)
    node.verify_directly_issued_by(ca)
    assert (
        ExtendedKeyUsageOID.CLIENT_AUTH
        in control.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    )
    assert (
        ExtendedKeyUsageOID.SERVER_AUTH
        in node.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    )
    assert (tmp_path / "node-5-key.pem").exists()
