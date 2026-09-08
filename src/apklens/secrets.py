"""Conservative, redaction-first hardcoded secret detection."""

from __future__ import annotations

import re

from .models import Confidence, SecurityFinding, Severity
from .resources import TextSource

_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.IGNORECASE
)
_GITHUB_TOKEN_PATTERN = re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,255}\b")
_AWS_SECRET_PATTERN = re.compile(
    r"\baws_secret_access_key\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})",
    re.IGNORECASE,
)
_AWS_ACCESS_KEY_PATTERN = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_ASSIGNMENT_PATTERNS: tuple[tuple[str, str, str, Severity, Confidence, re.Pattern[str]], ...] = (
    (
        "APK-SECRET-004",
        "Possible hardcoded client secret",
        "client secret",
        Severity.MEDIUM,
        Confidence.HIGH,
        re.compile(
            r"\b(?:client[_-]?secret|api[_-]?secret)\s*[:=]\s*[\"']?([A-Za-z0-9_./+=-]{16,})",
            re.IGNORECASE,
        ),
    ),
    (
        "APK-SECRET-005",
        "Possible hardcoded API key",
        "API key",
        Severity.MEDIUM,
        Confidence.MEDIUM,
        re.compile(
            r"\b(?:api[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*[\"']?([A-Za-z0-9_./+=-]{16,})",
            re.IGNORECASE,
        ),
    ),
    (
        "APK-SECRET-006",
        "Possible hardcoded password",
        "password",
        Severity.MEDIUM,
        Confidence.MEDIUM,
        re.compile(
            r"\b(?:password|passwd|pwd)\s*[:=]\s*[\"']?([^\s\"';]{8,})",
            re.IGNORECASE,
        ),
    ),
)


def redact_secret(value: str) -> str:
    """Return deterministic evidence that cannot reveal a full credential."""

    if len(value) <= 8:
        return "REDACTED"
    return f"{value[:4]}…{value[-4:]}"


def _is_placeholder(value: str) -> bool:
    normalized = value.casefold()
    placeholders = (
        "example",
        "sample",
        "placeholder",
        "changeme",
        "your_",
        "replace_",
        "<",
        "${",
        "{{",
        "dummy",
    )
    return any(marker in normalized for marker in placeholders)


def _finding(
    *,
    finding_id: str,
    title: str,
    severity: Severity,
    confidence: Confidence,
    secret_type: str,
    value: str | None,
    location: str,
) -> SecurityFinding:
    evidence = f"{secret_type}: {redact_secret(value)}" if value else secret_type
    return SecurityFinding(
        id=finding_id,
        title=title,
        severity=severity,
        confidence=confidence,
        category="secrets",
        description=(
            "A credential-like value is embedded in APK data. Static evidence "
            "cannot establish whether it is active, but it should be reviewed."
        ),
        evidence=evidence,
        location=location,
        remediation=(
            "Remove active credentials from the client and rotate any exposed value; "
            "retrieve secrets from an appropriate server-side control instead."
        ),
    )


def detect_secrets(sources: list[TextSource]) -> list[SecurityFinding]:
    """Detect high-signal credential patterns without exposing their values.

    Generic words such as ``token`` or ``password`` never trigger a finding on
    their own: an assignment plus a non-placeholder value of meaningful length
    is required. Findings are deduplicated by detector and full in-memory value
    before they are redacted for all output models.
    """

    findings: list[SecurityFinding] = []
    seen: set[tuple[str, str]] = set()

    def add_once(finding: SecurityFinding, raw_value: str) -> None:
        key = (finding.id, raw_value)
        if key not in seen:
            seen.add(key)
            findings.append(finding)

    for source in sources:
        if _PRIVATE_KEY_PATTERN.search(source.text):
            add_once(
                _finding(
                    finding_id="APK-SECRET-001",
                    title="Embedded private key material",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    secret_type="private key header",
                    value=None,
                    location=source.location,
                ),
                "private-key-header",
            )
        for match in _GITHUB_TOKEN_PATTERN.finditer(source.text):
            value = match.group(0)
            add_once(
                _finding(
                    finding_id="APK-SECRET-002",
                    title="Possible hardcoded GitHub token",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    secret_type="GitHub token",
                    value=value,
                    location=source.location,
                ),
                value,
            )
        for match in _AWS_SECRET_PATTERN.finditer(source.text):
            value = match.group(1)
            if not _is_placeholder(value):
                add_once(
                    _finding(
                        finding_id="APK-SECRET-003",
                        title="Possible hardcoded AWS secret access key",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        secret_type="AWS secret access key",
                        value=value,
                        location=source.location,
                    ),
                    value,
                )
        for match in _AWS_ACCESS_KEY_PATTERN.finditer(source.text):
            value = match.group(0)
            add_once(
                _finding(
                    finding_id="APK-SECRET-007",
                    title="Possible embedded AWS access key ID",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    secret_type="AWS access key ID",
                    value=value,
                    location=source.location,
                ),
                value,
            )
        for match in _JWT_PATTERN.finditer(source.text):
            value = match.group(0)
            add_once(
                _finding(
                    finding_id="APK-SECRET-008",
                    title="Possible embedded JSON Web Token",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    secret_type="JWT",
                    value=value,
                    location=source.location,
                ),
                value,
            )
        for finding_id, title, secret_type, severity, confidence, pattern in _ASSIGNMENT_PATTERNS:
            for match in pattern.finditer(source.text):
                value = match.group(1)
                if not _is_placeholder(value):
                    add_once(
                        _finding(
                            finding_id=finding_id,
                            title=title,
                            severity=severity,
                            confidence=confidence,
                            secret_type=secret_type,
                            value=value,
                            location=source.location,
                        ),
                        value,
                    )
    return sorted(
        findings,
        key=lambda finding: (finding.id, finding.location or "", finding.evidence or ""),
    )
