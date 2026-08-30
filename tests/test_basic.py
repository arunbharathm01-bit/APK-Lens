"""Unit tests for APKLens utilities and parser-independent analysis."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from xml.etree import ElementTree as ET
from zipfile import ZipFile

import pytest

from apklens.apk import APKPathError, calculate_sha256, validate_apk_path
from apklens.manifest import (
    classify_permission,
    extract_application_info,
    extract_manifest_info,
)
from apklens.models import AnalysisResult, ApplicationInfo, ComponentInfo, ManifestInfo
from apklens.native import extract_native_libraries, native_library_from_path
from apklens.report import JSONReporter
from apklens.security import analyze_security


def test_calculate_sha256_streams_file_content(tmp_path: Path) -> None:
    apk_path = tmp_path / "sample.apk"
    content = b"APKLens test content" * 100
    apk_path.write_bytes(content)

    assert calculate_sha256(apk_path, chunk_size=7) == hashlib.sha256(content).hexdigest()


def test_validate_apk_path_rejects_missing_paths_and_directories(tmp_path: Path) -> None:
    with pytest.raises(APKPathError, match="not found"):
        validate_apk_path(tmp_path / "missing.apk")
    with pytest.raises(APKPathError, match="not a file"):
        validate_apk_path(tmp_path)


def test_default_models_are_json_serializable() -> None:
    rendered = JSONReporter(AnalysisResult()).render()
    assert json.loads(rendered) == {
        "apk": {"filename": "", "sha256": "", "size_bytes": 0},
        "application": {
            "allow_backup": None,
            "backup_agent": None,
            "data_extraction_rules": None,
            "debuggable": False,
            "full_backup_content": None,
            "min_sdk": None,
            "package_name": None,
            "target_sdk": None,
            "version_code": None,
            "version_name": None,
        },
        "dex": {"class_count": None, "file_count": 0, "total_size_bytes": 0},
        "findings": [],
        "manifest": {"activities": [], "providers": [], "receivers": [], "services": []},
        "native": {"libraries": []},
        "permissions": [],
    }


def test_native_library_detection_uses_apk_member_paths(tmp_path: Path) -> None:
    apk_path = tmp_path / "native.apk"
    with ZipFile(apk_path, "w") as archive:
        archive.writestr("lib/arm64-v8a/libnative.so", b"a" * 12)
        archive.writestr("lib/x86_64/libother.so", b"b" * 4)
        archive.writestr("assets/libnotnative.so", b"c")

    libraries = extract_native_libraries(apk_path)
    assert [(item.abi, item.filename, item.size_bytes) for item in libraries.libraries] == [
        ("arm64-v8a", "libnative.so", 12),
        ("x86_64", "libother.so", 4),
    ]
    assert native_library_from_path("lib/x86/libthing.so", 3) is not None
    assert native_library_from_path("lib/x86/nested/libthing.so", 3) is None


@pytest.mark.parametrize(
    ("permission", "category"),
    [
        ("android.permission.INTERNET", "network"),
        ("android.permission.CAMERA", "camera"),
        ("android.permission.ACCESS_FINE_LOCATION", "location"),
        ("com.example.CUSTOM_PERMISSION", None),
    ],
)
def test_permission_classification(permission: str, category: str | None) -> None:
    assert classify_permission(permission) == category


def test_security_findings_cover_debuggable_and_unprotected_export() -> None:
    manifest = ManifestInfo(
        activities=[
            ComponentInfo(name="example.PublicActivity", exported=True),
            ComponentInfo(
                name="example.ProtectedActivity",
                exported=True,
                permission="example.permission.ACCESS",
            ),
            ComponentInfo(name="example.UnknownActivity", exported=None),
        ]
    )
    findings = analyze_security(ApplicationInfo(debuggable=True), manifest)

    assert [(finding.severity, finding.title) for finding in findings] == [
        ("LOW", "Debuggable flag: true"),
        ("MEDIUM", "Exported component without permission"),
    ]
    assert findings[1].component_name == "example.PublicActivity"


class _ParserFixture:
    def __init__(self, manifest: ET.Element) -> None:
        self.manifest = manifest

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


def test_manifest_handles_explicit_and_inferred_exported_states() -> None:
    namespace = "http://schemas.android.com/apk/res/android"
    manifest = ET.fromstring(
        f"""
        <manifest xmlns:android="{namespace}">
          <application android:debuggable="false">
            <activity android:name=".Launcher"><intent-filter /></activity>
            <service android:name="Sync" android:exported="false" />
            <provider android:name="Content" />
          </application>
        </manifest>
        """
    )
    parser = _ParserFixture(manifest)
    application = extract_application_info(parser)
    result = extract_manifest_info(parser, application.package_name, application.target_sdk)

    assert application.debuggable is False
    assert [(item.name, item.exported, item.exported_source) for item in result.activities] == [
        ("com.example.app.Launcher", True, "inferred_from_intent_filter")
    ]
    assert result.services[0].exported is False
    assert result.providers[0].exported is False
    assert result.providers[0].exported_source == "inferred_provider_default"
