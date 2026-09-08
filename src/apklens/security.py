"""Manifest-derived, evidence-backed security checks."""

from __future__ import annotations

from .models import (
    AnalysisResult,
    ApplicationInfo,
    CleartextTrafficState,
    Confidence,
    ManifestInfo,
    SecurityFinding,
    Severity,
)


def analyze_security(
    application: ApplicationInfo, manifest: ManifestInfo
) -> list[SecurityFinding]:
    """Run deterministic manifest checks.

    Findings are observations, not a complete vulnerability assessment. In
    particular, only components whose exported state can be determined to be
    true are reported.
    """

    findings = [
        SecurityFinding(
            id="APK-MANIFEST-001",
            title=f"Debuggable flag: {str(application.debuggable).lower()}",
            severity=Severity.LOW if application.debuggable else Severity.INFO,
            confidence=Confidence.HIGH,
            category="manifest",
            description=(
                "The application allows debugging in production builds."
                if application.debuggable
                else "The application is not marked as debuggable."
            ),
            evidence=f"android:debuggable={str(application.debuggable).lower()}",
            remediation=(
                "Disable android:debuggable for production builds."
                if application.debuggable
                else None
            ),
        )
    ]

    for component_type, component in manifest.components:
        if component.exported is True and not component.permission:
            findings.append(
                SecurityFinding(
                    id="APK-MANIFEST-002",
                    title="Exported component without permission",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    category="manifest",
                    description=(
                        "This component is exported and does not declare an explicit "
                        "protection permission."
                    ),
                    evidence=(
                        "android:exported=true"
                        if component.exported_source == "explicit"
                        else f"exported inferred from {component.exported_source}"
                    ),
                    component_type=component_type,
                    component_name=component.name,
                    remediation=(
                        "Set android:exported=false when external access is unnecessary, "
                        "or require an appropriate protection permission."
                    ),
                )
            )

    backup_fields = (
        application.allow_backup,
        application.backup_agent,
        application.full_backup_content,
        application.data_extraction_rules,
    )
    if any(value is not None for value in backup_fields):
        details: list[str] = []
        if application.allow_backup is not None:
            details.append(f"allowBackup={str(application.allow_backup).lower()}")
        if application.backup_agent:
            details.append("backupAgent declared")
        if application.full_backup_content:
            details.append("fullBackupContent declared")
        if application.data_extraction_rules:
            details.append("dataExtractionRules declared")
        findings.append(
            SecurityFinding(
                id="APK-MANIFEST-003",
                title="Backup configuration declared",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                category="manifest",
                description=(
                    "The manifest declares backup-related configuration. This is an "
                    "informational observation, not a vulnerability by itself."
                ),
                evidence="; ".join(details),
                remediation="Review backup policy and ensure sensitive data is excluded.",
            )
        )
    if application.cleartext_traffic is CleartextTrafficState.ENABLED:
        findings.append(
            SecurityFinding(
                id="APK-NET-001",
                title="Cleartext traffic allowed",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category="network",
                description=(
                    "The application explicitly permits non-TLS network connections. "
                    "This does not prove that sensitive data is transmitted over HTTP."
                ),
                evidence="android:usesCleartextTraffic=true",
                remediation=(
                    "Disable cleartext traffic and use TLS for network communication "
                    "unless a narrowly reviewed exception is required."
                ),
            )
        )
    return findings


def add_security_findings(result: AnalysisResult) -> AnalysisResult:
    """Populate ``result`` with its manifest-derived security observations."""

    result.findings = analyze_security(result.application, result.manifest)
    return result
