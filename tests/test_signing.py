"""Tests for offline signing certificate extraction."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from zipfile import ZipFile

import pytest

from apklens.signing import analyze_signing, extract_signing_info


class _SigningParser:
    def __init__(self, certificate: bytes) -> None:
        self.certificate = certificate

    def get_certificates_der_v2(self) -> list[bytes]:
        return [self.certificate]

    def get_certificates_der_v3(self) -> list[bytes]:
        return []

    def get_certificates(self) -> list[bytes]:
        return []


def _debug_certificate_der() -> bytes:
    cryptography = pytest.importorskip("cryptography")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Android Debug")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
        .sign(private_key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


def test_extracts_certificate_metadata_and_debug_signal(tmp_path: Path) -> None:
    apk_path = tmp_path / "signed.apk"
    with ZipFile(apk_path, "w") as archive:
        archive.writestr("META-INF/CERT.RSA", b"signature-block")
    signing = extract_signing_info(apk_path, _SigningParser(_debug_certificate_der()))

    assert signing.signature_schemes == ["v1", "v2"]
    assert signing.certificates[0].subject == "CN=Android Debug"
    assert len(signing.certificates[0].sha256_fingerprint) == 64
    assert [finding.id for finding in analyze_signing(signing)] == ["APK-SIGN-001"]


def test_handles_missing_certificate_metadata(tmp_path: Path) -> None:
    apk_path = tmp_path / "unsigned.apk"
    with ZipFile(apk_path, "w"):
        pass

    assert extract_signing_info(apk_path, _SigningParser(b"not-a-certificate")).certificates == []
