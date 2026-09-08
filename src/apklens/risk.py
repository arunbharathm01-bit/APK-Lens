"""Explainable, deterministic risk scoring for APKLens findings."""

from __future__ import annotations

from .models import (
    AnalysisSummary,
    Confidence,
    RiskContribution,
    SecurityFinding,
    Severity,
)

# The score expresses prioritisation, not exploitability or a security verdict.
# Base impact reflects the finding severity; confidence scales that impact only
# when the available static evidence is less conclusive.
_SEVERITY_POINTS: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 5,
    Severity.MEDIUM: 10,
    Severity.HIGH: 20,
}
_CONFIDENCE_MULTIPLIERS: dict[Confidence, float] = {
    Confidence.LOW: 0.4,
    Confidence.MEDIUM: 0.7,
    Confidence.HIGH: 1.0,
}


def _finding_sort_key(finding: SecurityFinding) -> tuple[str, str, str, str]:
    return (
        finding.id,
        finding.title,
        finding.location or "",
        finding.component_name or "",
    )


def score_finding(finding: SecurityFinding) -> int:
    """Return this finding's documented risk contribution before the score cap."""

    return round(
        _SEVERITY_POINTS[finding.severity]
        * _CONFIDENCE_MULTIPLIERS[finding.confidence]
    )


def assess_risk(findings: list[SecurityFinding]) -> AnalysisSummary:
    """Build a bounded score and itemised contributors from static findings.

    Severity bases are INFO=0, LOW=5, MEDIUM=10, and HIGH=20. Confidence
    multipliers are LOW=0.4, MEDIUM=0.7, and HIGH=1.0. The final total is
    capped at 100 so that the result remains a prioritisation aid.
    """

    severity_counts = {severity.value: 0 for severity in Severity}
    contributions: list[RiskContribution] = []
    uncapped_score = 0
    for finding in sorted(findings, key=_finding_sort_key):
        severity_counts[finding.severity.value] += 1
        points = score_finding(finding)
        if points:
            contributions.append(
                RiskContribution(
                    points=points,
                    finding_id=finding.id,
                    title=finding.title,
                )
            )
            uncapped_score += points
    return AnalysisSummary(
        risk_score=min(100, uncapped_score),
        severity_counts=severity_counts,
        contributions=contributions,
    )
