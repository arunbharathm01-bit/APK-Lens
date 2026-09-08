"""Tests for deterministic and explainable risk scoring."""

from __future__ import annotations

from apklens.models import Confidence, SecurityFinding, Severity
from apklens.risk import assess_risk, score_finding


def test_risk_uses_documented_severity_and_confidence_weights() -> None:
    findings = [
        SecurityFinding("debug", "Debuggable", Severity.LOW, Confidence.HIGH),
        SecurityFinding("export", "Exported", Severity.MEDIUM, Confidence.MEDIUM),
        SecurityFinding("cleartext", "Cleartext", Severity.MEDIUM, Confidence.HIGH),
    ]

    summary = assess_risk(findings)
    assert summary.risk_score == 22
    assert [contribution.points for contribution in summary.contributions] == [10, 5, 7]
    assert summary.severity_counts == {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 0}
    assert score_finding(findings[1]) == 7


def test_risk_score_is_bounded_at_100() -> None:
    findings = [
        SecurityFinding(f"high-{index}", "High signal", Severity.HIGH, Confidence.HIGH)
        for index in range(6)
    ]

    assert assess_risk(findings).risk_score == 100
