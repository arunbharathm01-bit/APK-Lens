"""Presentation-only reporters for normalized APK analysis results."""

from __future__ import annotations

import json
from enum import Enum
from typing import Protocol

from .models import AnalysisResult, PermissionScope, SecurityFinding, Severity
from .version import __version__


class Reporter(Protocol):
    """A renderer for an :class:`AnalysisResult`."""

    def render(self) -> str:
        """Return the fully rendered report."""


def _display(value: object | None) -> str:
    if value is None or value == "":
        return "N/A"
    if isinstance(value, Enum):
        return str(value.value)
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)


def _format_bytes(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    units = ("KB", "MB", "GB", "TB")
    value = float(size_bytes)
    for unit in units:
        value /= 1024
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}"
    return f"{size_bytes} B"


def _finding_icon(finding: SecurityFinding) -> str:
    return "⚠" if finding.severity in {Severity.MEDIUM, Severity.HIGH} else "ℹ"


def _severity_sort_key(finding: SecurityFinding) -> tuple[int, str, str]:
    order = {
        Severity.HIGH: 0,
        Severity.MEDIUM: 1,
        Severity.LOW: 2,
        Severity.INFO: 3,
    }
    return (order[finding.severity], finding.id, finding.location or "")


class TerminalReporter:
    """Render a readable, deterministic v0.2 report for a terminal."""

    def __init__(self, result: AnalysisResult) -> None:
        self.result = result

    def _render_permissions(self) -> list[str]:
        labels = {
            PermissionScope.ANDROID: "Android/system",
            PermissionScope.APPLICATION: "Application-defined",
            PermissionScope.UNKNOWN: "Other or unclassified",
        }
        groups = {scope: [] for scope in PermissionScope}
        for permission in self.result.permissions:
            groups[permission.scope].append(permission)

        lines = ["Permissions"]
        for scope in PermissionScope:
            permissions = groups[scope]
            if not permissions:
                continue
            lines.append(f"  {labels[scope]}")
            for permission in permissions:
                details = [
                    value
                    for value in (permission.category, permission.protection_level.value)
                    if value and value != "unknown"
                ]
                suffix = f" ({', '.join(details)})" if details else ""
                lines.append(f"    {permission.name}{suffix}")
        if len(lines) == 1:
            lines.append("  (none)")
        return lines

    def _render_network(self) -> list[str]:
        network = self.result.network
        lines = [
            "Network Indicators",
            f"  URLs              {len(network.urls)}",
            f"  Unique domains    {len(network.domains)}",
        ]
        if network.domains:
            lines.extend(("", "  Domains"))
            lines.extend(f"    {domain}" for domain in network.domains)
        if network.http_urls:
            lines.extend(("", "  HTTP"))
            lines.extend(f"    {url}" for url in network.http_urls)
        return lines

    def _render_indicators(self) -> list[str]:
        lines = ["Security Indicators"]
        if not self.result.indicators:
            lines.append("  (none)")
            return lines
        for indicator in self.result.indicators:
            locations = ", ".join(indicator.locations)
            suffix = f" ({locations})" if locations else ""
            lines.append(
                f"  {indicator.category}: {indicator.indicator} — {indicator.references}{suffix}"
            )
        return lines

    def _render_signing(self) -> list[str]:
        signing = self.result.signing
        lines = ["Signing Certificate"]
        if signing.signature_schemes:
            lines.append(f"  Schemes       {', '.join(signing.signature_schemes)}")
        if not signing.certificates:
            lines.append("  (no certificate metadata available)")
            return lines
        for index, certificate in enumerate(signing.certificates, start=1):
            if index > 1:
                lines.append("")
            lines.extend(
                (
                    f"  Certificate {index}",
                    f"    Subject       {_display(certificate.subject)}",
                    f"    Issuer        {_display(certificate.issuer)}",
                    f"    Serial        {_display(certificate.serial_number)}",
                    f"    SHA-256       {_display(certificate.sha256_fingerprint)}",
                    f"    Valid From    {_display(certificate.valid_from)}",
                    f"    Valid Until   {_display(certificate.valid_until)}",
                )
            )
        return lines

    def _render_findings(self) -> list[str]:
        lines = ["Security Findings", f"  Findings         {len(self.result.findings)}"]
        last_severity: Severity | None = None
        for finding in sorted(self.result.findings, key=_severity_sort_key):
            if finding.severity is not last_severity:
                lines.extend(("", f"  {finding.severity.value}"))
                last_severity = finding.severity
            lines.append(f"    {_finding_icon(finding)} {finding.title} [{finding.id}]")
            lines.append(f"      Confidence: {finding.confidence.value}")
            if finding.location:
                lines.append(f"      Location: {finding.location}")
            if finding.component_type and finding.component_name:
                lines.append(f"      Component: {finding.component_type}: {finding.component_name}")
            if finding.evidence:
                lines.append(f"      Evidence: {finding.evidence}")
            lines.append(f"      {finding.description}")
            if finding.remediation:
                lines.append(f"      Remediation: {finding.remediation}")
        return lines

    def _render_risk_summary(self) -> list[str]:
        summary = self.result.summary
        lines = ["Risk Summary", f"  Risk Score       {summary.risk_score} / 100"]
        counts = "  ".join(
            f"{severity} {summary.severity_counts.get(severity, 0)}"
            for severity in ("HIGH", "MEDIUM", "LOW", "INFO")
        )
        lines.append(f"  {counts}")
        if summary.contributions:
            lines.extend(("", "  Contributors"))
            lines.extend(
                f"    +{contribution.points:>2}  {contribution.title} [{contribution.finding_id}]"
                for contribution in summary.contributions
            )
        return lines

    def render(self) -> str:
        """Return the human-readable report without printing it."""

        result = self.result
        lines = [f"APKLens v{__version__}", "─" * 40, "", "APK"]
        lines.extend(
            (
                f"  File          {_display(result.apk.filename)}",
                f"  Size          {_format_bytes(result.apk.size_bytes)}",
                f"  SHA-256       {_display(result.apk.sha256)}",
                "",
                "Application",
                f"  Package       {_display(result.application.package_name)}",
                f"  Version       {_display(result.application.version_name)}",
                f"  Version Code  {_display(result.application.version_code)}",
                f"  Min SDK       {_display(result.application.min_sdk)}",
                f"  Target SDK    {_display(result.application.target_sdk)}",
                f"  Cleartext     {_display(result.application.cleartext_traffic)}",
                "",
                "Manifest",
                f"  Activities       {len(result.manifest.activities)}",
                f"  Services          {len(result.manifest.services)}",
                f"  Receivers         {len(result.manifest.receivers)}",
                f"  Providers         {len(result.manifest.providers)}",
                "",
            )
        )
        lines.extend(self._render_permissions())
        lines.extend(
            (
                "",
                "DEX",
                f"  Files            {result.dex.file_count}",
                f"  Total size       {_format_bytes(result.dex.total_size_bytes)}",
                f"  Total classes    {_display(result.dex.class_count)}",
                "",
                "Native Libraries",
            )
        )
        abi_counts = result.native.counts_by_abi()
        if abi_counts:
            lines.extend(f"  {abi:<16} {count}" for abi, count in abi_counts.items())
        else:
            lines.append("  (none)")
        for section in (
            self._render_network(),
            self._render_indicators(),
            self._render_signing(),
            self._render_findings(),
            self._render_risk_summary(),
        ):
            lines.extend(("", *section))
        return "\n".join(lines)


class JSONReporter:
    """Render an :class:`AnalysisResult` as valid, stable JSON."""

    def __init__(self, result: AnalysisResult) -> None:
        self.result = result

    def render(self) -> str:
        """Return pretty, machine-readable JSON with deterministic key ordering."""

        return json.dumps(self.result.to_dict(), indent=2, sort_keys=True)
