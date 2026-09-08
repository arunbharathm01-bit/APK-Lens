"""Evidence-backed WebView configuration checks."""

from __future__ import annotations

import re

from .models import Confidence, SecurityFinding, Severity
from .resources import TextSource

_WEBVIEW_CHECKS: tuple[
    tuple[str, str, Severity, str, str, str, re.Pattern[str]], ...
] = (
    (
        "APK-WEBVIEW-001",
        "WebView JavaScript enabled",
        Severity.MEDIUM,
        "webview",
        "setJavaScriptEnabled(true)",
        "Review whether JavaScript is necessary and ensure only trusted content is loaded.",
        re.compile(r"setJavaScriptEnabled\s*\(\s*true\s*\)", re.IGNORECASE),
    ),
    (
        "APK-WEBVIEW-002",
        "WebView universal file access enabled",
        Severity.MEDIUM,
        "webview",
        "setAllowUniversalAccessFromFileURLs(true)",
        "Disable universal file access unless a narrowly reviewed use case requires it.",
        re.compile(
            r"setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)",
            re.IGNORECASE,
        ),
    ),
    (
        "APK-WEBVIEW-003",
        "WebView file access enabled",
        Severity.LOW,
        "webview",
        "setAllowFileAccess(true)",
        "Restrict file access when the WebView can load untrusted content.",
        re.compile(r"setAllowFileAccess\s*\(\s*true\s*\)", re.IGNORECASE),
    ),
)


def analyze_webview(sources: list[TextSource]) -> list[SecurityFinding]:
    """Report only explicit ``true`` WebView configuration evidence.

    A WebView class or method reference alone is left as an API indicator. This
    avoids treating ordinary WebView use as a vulnerability.
    """

    findings: list[SecurityFinding] = []
    for finding_id, title, severity, category, evidence, remediation, pattern in _WEBVIEW_CHECKS:
        for source in sources:
            if pattern.search(source.text):
                findings.append(
                    SecurityFinding(
                        id=finding_id,
                        title=title,
                        severity=severity,
                        confidence=Confidence.HIGH,
                        category=category,
                        description=(
                            "The APK contains an explicit WebView configuration that "
                            "enables this capability. Review its content-loading context."
                        ),
                        evidence=evidence,
                        location=source.location,
                        remediation=remediation,
                    )
                )
                break
    return findings
