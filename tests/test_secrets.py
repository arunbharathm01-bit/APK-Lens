"""Tests for conservative, redaction-first secret detection."""

from __future__ import annotations

import json

from apklens.models import AnalysisResult
from apklens.report import JSONReporter
from apklens.resources import TextSource
from apklens.secrets import detect_secrets, redact_secret


def test_detects_github_token_and_redacts_every_report_surface() -> None:
    token = "ghp_" + "a" * 36
    findings = detect_secrets([TextSource("classes.dex", f"const value = {token}")])

    assert len(findings) == 1
    assert findings[0].id == "APK-SECRET-002"
    assert findings[0].evidence == f"GitHub token: {redact_secret(token)}"
    rendered = JSONReporter(AnalysisResult(findings=findings)).render()
    assert token not in rendered
    assert json.loads(rendered)["findings"][0]["location"] == "classes.dex"


def test_does_not_flag_words_short_values_or_placeholders() -> None:
    sources = [
        TextSource("assets/normal.txt", "token password secret key"),
        TextSource("assets/short.txt", "password=short"),
        TextSource("assets/example.txt", "api_key=YOUR_API_KEY_REPLACE_ME"),
    ]

    assert detect_secrets(sources) == []


def test_detects_private_key_header_without_exposing_key_material() -> None:
    source = TextSource(
        "assets/key.pem",
        "-----BEGIN PRIVATE KEY-----\nthis-must-not-be-reported\n-----END PRIVATE KEY-----",
    )
    findings = detect_secrets([source])

    assert findings[0].id == "APK-SECRET-001"
    assert findings[0].evidence == "private key header"
    assert "this-must-not-be-reported" not in JSONReporter(
        AnalysisResult(findings=findings)
    ).render()
