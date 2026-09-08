"""Tests for evidence-backed WebView checks."""

from __future__ import annotations

from apklens.resources import TextSource
from apklens.webview import analyze_webview


def test_detects_explicit_webview_javascript_enablement() -> None:
    findings = analyze_webview(
        [TextSource("assets/settings.txt", "webView.setJavaScriptEnabled(true)")]
    )

    assert [(finding.id, finding.evidence, finding.location) for finding in findings] == [
        ("APK-WEBVIEW-001", "setJavaScriptEnabled(true)", "assets/settings.txt")
    ]


def test_does_not_flag_webview_class_reference_alone() -> None:
    assert analyze_webview([TextSource("classes.dex", "Landroid/webkit/WebView;")]) == []
