"""Tests for conservative permission intelligence."""

from __future__ import annotations

from apklens.manifest import extract_permissions
from apklens.models import PermissionProtection, PermissionScope


class _PermissionParser:
    def get_permissions(self) -> list[str]:
        return [
            "com.example.app.INTERNAL",
            "android.permission.CAMERA",
            "android.permission.INTERNET",
            "vendor.permission.CUSTOM",
        ]

    def get_declared_permissions(self) -> list[str]:
        return ["com.example.app.INTERNAL"]


def test_permission_scope_and_protection_are_explicit() -> None:
    permissions = extract_permissions(_PermissionParser(), "com.example.app")
    by_name = {permission.name: permission for permission in permissions}

    assert by_name["android.permission.CAMERA"].scope is PermissionScope.ANDROID
    assert by_name["android.permission.CAMERA"].protection_level is PermissionProtection.DANGEROUS
    assert by_name["android.permission.INTERNET"].protection_level is PermissionProtection.NORMAL
    assert by_name["com.example.app.INTERNAL"].scope is PermissionScope.APPLICATION
    assert by_name["vendor.permission.CUSTOM"].scope is PermissionScope.UNKNOWN
