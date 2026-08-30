"""Small, deterministic security checks for normalized analysis results."""

from __future__ import annotations

from .models import AnalysisResult, ApplicationInfo, ManifestInfo, SecurityFinding


def analyze_security(
    application: ApplicationInfo, manifest: ManifestInfo
) -> list[SecurityFinding]:
    """Run the intentionally limited v0.1 security checks.

    Findings are observations, not a complete vulnerability assessment. In
    particular, only components whose exported state can be determined to be
    true are reported.
    """

    findings = [
        SecurityFinding(
            severity="LOW" if application.debuggable else "INFO",
            title=f"Debuggable flag: {str(application.debuggable).lower()}",
            reason=(
                "The application allows debugging in production builds."
                if application.debuggable
                else "The application is not marked as debuggable."
            ),
        )
    ]

    for component_type, component in manifest.components:
        if component.exported is True and not component.permission:
            findings.append(
                SecurityFinding(
                    severity="MEDIUM",
                    title="Exported component without permission",
                    reason=(
                        "This component is exported and does not declare an explicit "
                        "protection permission."
                    ),
                    component_type=component_type,
                    component_name=component.name,
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
                severity="INFO",
                title="Backup configuration declared",
                reason="; ".join(details),
            )
        )
    return findings


def add_security_findings(result: AnalysisResult) -> AnalysisResult:
    """Populate and return ``result`` with the v0.1 security observations."""

    result.findings = analyze_security(result.application, result.manifest)
    return result
