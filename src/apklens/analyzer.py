"""Orchestration entry point for static APK analysis."""

from __future__ import annotations

from pathlib import Path

from .apk import APKParseError, extract_apk_info, load_apk_parser, open_apk_archive, validate_apk_path
from .dex import extract_dex_info
from .manifest import extract_application_info, extract_manifest_info, extract_permissions
from .models import AnalysisResult
from .native import extract_native_libraries
from .security import add_security_findings


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
            permissions=extract_permissions(parser),
            dex=extract_dex_info(path, parser),
            native=extract_native_libraries(path),
        )
        return add_security_findings(result)


__all__ = ["APKAnalyzer", "APKParseError"]
