"""Presentation-only reporters for normalized APK analysis results."""

from __future__ import annotations

import json
from typing import Protocol

from .models import AnalysisResult, SecurityFinding


class Reporter(Protocol):
    """A renderer for an :class:`AnalysisResult`."""

    def render(self) -> str:
        """Return the fully rendered report."""


def _display(value: object | None) -> str:
    if value is None or value == "":
        return "N/A"
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
    return "⚠" if finding.severity in {"MEDIUM", "HIGH", "CRITICAL"} else "ℹ"


class TerminalReporter:
    """Render a concise, deterministic report intended for a terminal."""

    def __init__(self, result: AnalysisResult) -> None:
        self.result = result

    def render(self) -> str:
        """Return the human-readable report without printing it."""

        result = self.result
        lines = ["APKLens v0.1.0", "─" * 40, "", "APK"]
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
                "",
                "Manifest",
                f"  Activities       {len(result.manifest.activities)}",
                f"  Services          {len(result.manifest.services)}",
                f"  Receivers         {len(result.manifest.receivers)}",
                f"  Providers         {len(result.manifest.providers)}",
                "",
                "Permissions",
            )
        )
        if result.permissions:
            lines.extend(f"  {permission.name}" for permission in result.permissions)
        else:
            lines.append("  (none)")

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

        lines.extend(("", "Security", f"  Findings         {len(result.findings)}"))
        for finding in result.findings:
            lines.extend(("", f"  {_finding_icon(finding)} {finding.title}"))
            if finding.component_type and finding.component_name:
                lines.append(f"    {finding.component_type}: {finding.component_name}")
            lines.append(f"    {finding.reason}")
        return "\n".join(lines)


class JSONReporter:
    """Render an :class:`AnalysisResult` as valid, stable JSON."""

    def __init__(self, result: AnalysisResult) -> None:
        self.result = result

    def render(self) -> str:
        """Return pretty, machine-readable JSON with deterministic key ordering."""

        return json.dumps(self.result.to_dict(), indent=2, sort_keys=True)
