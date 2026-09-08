"""Tests for v0.2 manifest configuration analysis."""

from __future__ import annotations

from xml.etree import ElementTree as ET

import pytest

from apklens.manifest import extract_application_info
from apklens.models import CleartextTrafficState, ManifestInfo
from apklens.security import analyze_security


class _ManifestParser:
    def __init__(self, xml: str) -> None:
        self.manifest = ET.fromstring(xml)

    def get_package(self) -> str:
        return "com.example.app"

    def get_androidversion_name(self) -> str:
        return "1.0"

    def get_androidversion_code(self) -> str:
        return "1"

    def get_min_sdk_version(self) -> str:
        return "26"

    def get_target_sdk_version(self) -> str:
        return "35"

    def get_android_manifest_xml(self) -> ET.Element:
        return self.manifest


@pytest.mark.parametrize(
    ("attribute", "expected"),
    [
        ('android:usesCleartextTraffic="true"', CleartextTrafficState.ENABLED),
        ('android:usesCleartextTraffic="false"', CleartextTrafficState.DISABLED),
        ("", CleartextTrafficState.NOT_DECLARED),
        ('android:usesCleartextTraffic="maybe"', CleartextTrafficState.UNKNOWN),
    ],
)
def test_cleartext_traffic_state_is_not_inferred(
    attribute: str, expected: CleartextTrafficState
) -> None:
    parser = _ManifestParser(
        "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\">"
        f"<application {attribute} />"
        "</manifest>"
    )

    assert extract_application_info(parser).cleartext_traffic is expected


def test_explicit_cleartext_enablement_creates_a_finding() -> None:
    parser = _ManifestParser(
        "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\">"
        "<application android:usesCleartextTraffic=\"true\" />"
        "</manifest>"
    )
    findings = analyze_security(extract_application_info(parser), ManifestInfo())

    cleartext = next(finding for finding in findings if finding.id == "APK-NET-001")
    assert cleartext.evidence == "android:usesCleartextTraffic=true"
    assert cleartext.confidence.value == "HIGH"
