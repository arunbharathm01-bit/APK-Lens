"""APK signing certificate extraction using parser-provided static evidence."""

from __future__ import annotations

from datetime import timezone
from pathlib import Path
from typing import Any, Iterable
from zipfile import ZipFile

from .models import Confidence, SecurityFinding, Severity, SigningCertificate, SigningInfo


def _iter_values(value: Any) -> Iterable[Any]:
    if value is None:
        return ()
    if isinstance(value, (bytes, bytearray)):
        return (value,)
    try:
        return iter(value)
    except TypeError:
        return (value,)


def _parser_certificates(parser: Any) -> tuple[list[Any], list[str]]:
    """Retrieve certificate material across common Androguard APK APIs."""

    certificates: list[Any] = []
    schemes: list[str] = []
    for scheme, method_name in (("v3", "get_certificates_der_v3"), ("v2", "get_certificates_der_v2")):
        method = getattr(parser, method_name, None)
        if not callable(method):
            continue
        try:
            values = list(_iter_values(method()))
        except Exception:
            continue
        if values:
            certificates.extend(values)
            schemes.append(scheme)

    method = getattr(parser, "get_certificates", None)
    if callable(method):
        try:
            values = list(_iter_values(method()))
        except Exception:
            values = []
        if values:
            certificates.extend(values)
            schemes.append("v1")
    return certificates, schemes


def _to_der(value: Any) -> bytes | None:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    dump = getattr(value, "dump", None)
    if callable(dump):
        try:
            dumped = dump()
        except Exception:
            return None
        return bytes(dumped) if isinstance(dumped, (bytes, bytearray)) else None
    return None


def _format_datetime(value: Any) -> str | None:
    if value is None:
        return None
    if getattr(value, "tzinfo", None) is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def _certificate_from_der(der: bytes) -> SigningCertificate | None:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        certificate = x509.load_der_x509_certificate(der)
    except Exception:
        return None
    valid_from = getattr(certificate, "not_valid_before_utc", None)
    valid_until = getattr(certificate, "not_valid_after_utc", None)
    if valid_from is None:
        valid_from = certificate.not_valid_before
    if valid_until is None:
        valid_until = certificate.not_valid_after
    return SigningCertificate(
        subject=certificate.subject.rfc4514_string(),
        issuer=certificate.issuer.rfc4514_string(),
        serial_number=f"{certificate.serial_number:X}",
        sha256_fingerprint=certificate.fingerprint(hashes.SHA256()).hex(),
        valid_from=_format_datetime(valid_from),
        valid_until=_format_datetime(valid_until),
    )


def _has_v1_signature(path: str | Path) -> bool:
    with ZipFile(path) as archive:
        return any(
            entry.filename.upper().startswith("META-INF/")
            and entry.filename.upper().endswith((".RSA", ".DSA", ".EC"))
            for entry in archive.infolist()
        )


def extract_signing_info(path: str | Path, parser: Any) -> SigningInfo:
    """Extract signing certificate metadata without performing trust validation."""

    raw_certificates, schemes = _parser_certificates(parser)
    if _has_v1_signature(path):
        schemes.append("v1")

    certificates: list[SigningCertificate] = []
    seen_fingerprints: set[str] = set()
    for raw_certificate in raw_certificates:
        der = _to_der(raw_certificate)
        if der is None:
            continue
        certificate = _certificate_from_der(der)
        if certificate and certificate.sha256_fingerprint not in seen_fingerprints:
            seen_fingerprints.add(certificate.sha256_fingerprint)
            certificates.append(certificate)
    certificates.sort(key=lambda certificate: certificate.sha256_fingerprint)
    return SigningInfo(certificates=certificates, signature_schemes=sorted(set(schemes)))


def analyze_signing(signing: SigningInfo) -> list[SecurityFinding]:
    """Report reliable Android debug certificate evidence as a low-risk signal."""

    findings: list[SecurityFinding] = []
    for certificate in signing.certificates:
        certificate_names = f"{certificate.subject} {certificate.issuer}".casefold()
        if "android debug" not in certificate_names:
            continue
        findings.append(
            SecurityFinding(
                id="APK-SIGN-001",
                title="Android debug signing certificate detected",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                category="signing",
                description=(
                    "The APK is signed with an Android debug certificate, which is "
                    "strong evidence of a development build. This is not by itself a "
                    "vulnerability, but it should not normally be distributed as production."
                ),
                evidence=f"SHA-256: {certificate.sha256_fingerprint}",
                remediation="Sign production releases with the managed production signing key.",
            )
        )
    return findings
