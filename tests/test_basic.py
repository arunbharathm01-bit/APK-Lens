"""Unit tests for APKLens utilities and parser-independent analysis."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from xml.etree import ElementTree as ET
from zipfile import ZipFile

import pytest

from apklens.apk import (
    APKParseError,
    APKPathError,
    calculate_sha256,
    open_apk_archive,
    validate_apk_path,
)
from apklens.cli import main
from apklens.dex import extract_dex_info
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


def test_open_apk_archive_rejects_non_zip_files(tmp_path: Path) -> None:
    apk_path = tmp_path / "not-an-apk.apk"
    apk_path.write_bytes(b"not a ZIP archive")

    with pytest.raises(APKParseError, match="Invalid or corrupt APK archive"):
        open_apk_archive(apk_path)


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


def test_dex_info_counts_only_top_level_conventional_dex_files(tmp_path: Path) -> None:
    apk_path = tmp_path / "dex.apk"
    with ZipFile(apk_path, "w") as archive:
        archive.writestr("classes.dex", b"a" * 7)
        archive.writestr("classes2.dex", b"b" * 11)
        archive.writestr("assets/classes3.dex", b"c" * 13)
        archive.writestr("other.dex", b"d" * 17)

    dex = extract_dex_info(apk_path)
    assert (dex.file_count, dex.total_size_bytes, dex.class_count) == (2, 18, None)


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


def test_cli_json_errors_leave_stdout_machine_readable(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    missing_path = tmp_path / "missing.apk"

    assert main([str(missing_path), "--json"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == f"Error: APK file not found: {missing_path}\n"


def test_cli_reports_malformed_apks_without_parser_log_noise(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    apk_path = tmp_path / "empty.apk"
    with ZipFile(apk_path, "w"):
        pass

    assert main([str(apk_path)]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == f"Error: Invalid Android APK: {apk_path}\n"
