"""Orchestration entry point for static APK analysis."""

from __future__ import annotations

from pathlib import Path

from .apk import APKParseError, extract_apk_info, load_apk_parser, open_apk_archive, validate_apk_path
from .dex import extract_api_indicators, extract_dex_info
from .manifest import extract_application_info, extract_manifest_info, extract_permissions
from .models import AnalysisResult
from .native import extract_native_libraries
from .network import extract_network_info
from .resources import extract_text_sources
from .risk import assess_risk
from .secrets import detect_secrets
from .security import analyze_security
from .signing import analyze_signing, extract_signing_info
from .webview import analyze_webview


class APKAnalyzer:
    """Analyze one APK and return a normalized :class:`AnalysisResult`."""

    def __init__(self, apk_path: str | Path) -> None:
        self.apk_path = Path(apk_path)

    def analyze(self) -> AnalysisResult:
        """Validate, parse, and inspect the APK without executing any app code."""

        path = validate_apk_path(self.apk_path)
        # Validate ZIP structure before asking androguard for Android metadata.
        with open_apk_archive(path):
            pass

        parser = load_apk_parser(path)
        application = extract_application_info(parser)
        manifest = extract_manifest_info(
            parser, application.package_name, application.target_sdk
        )
        result = AnalysisResult(
            apk=extract_apk_info(path),
            application=application,
            manifest=manifest,
            permissions=extract_permissions(parser, application.package_name),
            dex=extract_dex_info(path, parser),
            native=extract_native_libraries(path),
        )
        text_sources = extract_text_sources(path)
        result.network = extract_network_info(text_sources)
        result.indicators = extract_api_indicators(path)
        result.signing = extract_signing_info(path, parser)

        findings = analyze_security(result.application, result.manifest)
        findings.extend(analyze_webview(text_sources))
        findings.extend(detect_secrets(text_sources))
        findings.extend(analyze_signing(result.signing))
        result.findings = sorted(
            findings,
            key=lambda finding: (
                finding.id,
                finding.location or "",
                finding.component_name or "",
                finding.evidence or "",
            ),
        )
        result.summary = assess_risk(result.findings)
        return result


__all__ = ["APKAnalyzer", "APKParseError"]
