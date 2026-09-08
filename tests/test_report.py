"""Tests for v0.2 terminal/JSON reporting and CLI pipe handling."""

from __future__ import annotations

import builtins
import json

from apklens import cli
from apklens.models import AnalysisResult, Confidence, NetworkInfo, SecurityFinding, Severity
from apklens.report import JSONReporter, TerminalReporter


def test_report_includes_v02_sections_and_never_leaks_raw_secret() -> None:
    raw_secret = "ghp_" + "x" * 36
    result = AnalysisResult(
        network=NetworkInfo(urls=["https://api.example.com"], domains=["api.example.com"]),
        findings=[
            SecurityFinding(
                id="APK-SECRET-002",
                title="Possible hardcoded GitHub token",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="secrets",
                description="Credential-like value observed.",
                evidence="GitHub token: ghp_…xxxx",
                location="classes.dex",
            )
        ],
    )

    terminal = TerminalReporter(result).render()
    payload = json.loads(JSONReporter(result).render())
    assert "Network Indicators" in terminal
    assert "Security Findings" in terminal
    assert "Risk Summary" in terminal
    assert raw_secret not in terminal
    assert payload["tool"]["version"] == "0.2.0"
    assert raw_secret not in json.dumps(payload)


def test_cli_handles_broken_pipe_without_traceback(monkeypatch: object) -> None:
    class _Analyzer:
        def __init__(self, _: str) -> None:
            pass

        def analyze(self) -> AnalysisResult:
            return AnalysisResult()

    class _Reporter:
        def __init__(self, _: AnalysisResult) -> None:
            pass

        def render(self) -> str:
            return "{}"

    class _Stream:
        closed = False

        def close(self) -> None:
            self.closed = True

    stream = _Stream()

    def _broken_print(*_: object, **__: object) -> None:
        raise BrokenPipeError

    monkeypatch.setattr(cli, "APKAnalyzer", _Analyzer)
    monkeypatch.setattr(cli, "JSONReporter", _Reporter)
    monkeypatch.setattr(cli.sys, "stdout", stream)
    monkeypatch.setattr(builtins, "print", _broken_print)

    assert cli.main(["sample.apk", "--json"]) == 0
    assert stream.closed is True
