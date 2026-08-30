"""Manifest and permission extraction with Android-aware defaults."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .models import ApplicationInfo, ComponentInfo, ManifestInfo, PermissionInfo

ANDROID_NAMESPACE = "http://schemas.android.com/apk/res/android"
ANDROID_ATTR = f"{{{ANDROID_NAMESPACE}}}"


def _get_method_value(parser: Any, method_name: str) -> str | None:
    method = getattr(parser, method_name, None)
    if not callable(method):
        return None
    try:
        value = method()
    except Exception:
        return None
    return str(value) if value is not None else None


def _attribute(element: Any, name: str) -> str | None:
    """Read an Android attribute from lxml, ElementTree, or mock elements."""

    get = getattr(element, "get", None)
    if not callable(get):
        return None
    for key in (f"{ANDROID_ATTR}{name}", f"android:{name}", name):
        value = get(key)
        if value is not None:
            return str(value)
    return None


def _as_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized in {"true", "1"}:
        return True
    if normalized in {"false", "0"}:
        return False
    return None


def _tag_name(element: Any) -> str:
    tag = str(getattr(element, "tag", ""))
    return tag.rsplit("}", maxsplit=1)[-1]


def _children(element: Any) -> Iterable[Any]:
    try:
        return iter(element)
    except TypeError:
        return ()


def _find_application(manifest: Any) -> Any | None:
    for child in _children(manifest):
        if _tag_name(child) == "application":
            return child
    return None


def _has_intent_filter(element: Any) -> bool:
    return any(_tag_name(child) == "intent-filter" for child in _children(element))


def _target_sdk_number(target_sdk: str | None) -> int | None:
    if target_sdk is None:
        return None
    try:
        return int(target_sdk)
    except ValueError:
        return None


def _component_exported(
    element: Any, component_type: str, target_sdk: str | None
) -> tuple[bool | None, str]:
    explicit = _as_bool(_attribute(element, "exported"))
    if explicit is not None:
        return explicit, "explicit"

    if component_type in {"activity", "service", "receiver"}:
        return _has_intent_filter(element), "inferred_from_intent_filter"

    target_sdk_number = _target_sdk_number(target_sdk)
    if component_type == "provider" and target_sdk_number is not None:
        return target_sdk_number < 17, "inferred_provider_default"

    return None, "unknown"


def _fully_qualified_name(name: str | None, package_name: str | None) -> str:
    if not name:
        return ""
    if not package_name or name.startswith(".") is False and "." in name:
        return name
    if name.startswith("."):
        return f"{package_name}{name}"
    return f"{package_name}.{name}"


def _component_info(
    element: Any, component_type: str, package_name: str | None, target_sdk: str | None
) -> ComponentInfo:
    exported, source = _component_exported(element, component_type, target_sdk)
    enabled = _as_bool(_attribute(element, "enabled"))
    return ComponentInfo(
        name=_fully_qualified_name(_attribute(element, "name"), package_name),
        exported=exported,
        exported_source=source,
        permission=_attribute(element, "permission"),
        enabled=True if enabled is None else enabled,
    )


def extract_application_info(parser: Any) -> ApplicationInfo:
    """Extract package metadata and application attributes from an androguard APK."""

    package_name = _get_method_value(parser, "get_package")
    application = ApplicationInfo(
        package_name=package_name,
        version_name=_get_method_value(parser, "get_androidversion_name"),
        version_code=_get_method_value(parser, "get_androidversion_code"),
        min_sdk=_get_method_value(parser, "get_min_sdk_version"),
        target_sdk=_get_method_value(parser, "get_target_sdk_version"),
    )

    manifest = get_manifest_xml(parser)
    app_element = _find_application(manifest) if manifest is not None else None
    if app_element is None:
        return application

    application.debuggable = _as_bool(_attribute(app_element, "debuggable")) is True
    application.allow_backup = _as_bool(_attribute(app_element, "allowBackup"))
    application.backup_agent = _attribute(app_element, "backupAgent")
    application.full_backup_content = _attribute(app_element, "fullBackupContent")
    application.data_extraction_rules = _attribute(app_element, "dataExtractionRules")
    return application


def get_manifest_xml(parser: Any) -> Any | None:
    """Retrieve parsed manifest XML from supported androguard versions."""

    method = getattr(parser, "get_android_manifest_xml", None)
    if not callable(method):
        return None
    try:
        return method()
    except Exception:
        return None


def extract_manifest_info(
    parser: Any, package_name: str | None, target_sdk: str | None
) -> ManifestInfo:
    """Extract manifest components and represent implicit exports explicitly."""

    manifest = get_manifest_xml(parser)
    application = _find_application(manifest) if manifest is not None else None
    if application is None:
        return ManifestInfo()

    component_fields = {
        "activity": "activities",
        "activity-alias": "activities",
        "service": "services",
        "receiver": "receivers",
        "provider": "providers",
    }
    extracted: dict[str, list[ComponentInfo]] = {
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
    }
    for element in _children(application):
        manifest_tag = _tag_name(element)
        field_name = component_fields.get(manifest_tag)
        if field_name is None:
            continue
        component_type = "activity" if manifest_tag == "activity-alias" else manifest_tag
        extracted[field_name].append(
            _component_info(element, component_type, package_name, target_sdk)
        )

    for components in extracted.values():
        components.sort(key=lambda component: component.name)
    return ManifestInfo(**extracted)


_PERMISSION_CATEGORIES: tuple[tuple[str, str], ...] = (
    ("CAMERA", "camera"),
    ("ACCESS_FINE_LOCATION", "location"),
    ("ACCESS_COARSE_LOCATION", "location"),
    ("ACCESS_BACKGROUND_LOCATION", "location"),
    ("READ_CONTACTS", "contacts"),
    ("WRITE_CONTACTS", "contacts"),
    ("GET_ACCOUNTS", "contacts"),
    ("POST_NOTIFICATIONS", "notifications"),
    ("BODY_SENSORS", "sensors"),
    ("ACTIVITY_RECOGNITION", "sensors"),
    ("READ_EXTERNAL_STORAGE", "storage"),
    ("WRITE_EXTERNAL_STORAGE", "storage"),
    ("MANAGE_EXTERNAL_STORAGE", "storage"),
)


def classify_permission(permission_name: str) -> str | None:
    """Classify a small, intentionally conservative set of permission families."""

    short_name = permission_name.rsplit(".", maxsplit=1)[-1]
    if short_name in {"INTERNET", "ACCESS_NETWORK_STATE", "CHANGE_NETWORK_STATE", "ACCESS_WIFI_STATE"}:
        return "network"
    if short_name.startswith(("READ_PHONE", "WRITE_APN", "CALL_", "ANSWER_", "PROCESS_OUTGOING")):
        return "phone"
    for marker, category in _PERMISSION_CATEGORIES:
        if short_name == marker:
            return category
    return None


def extract_permissions(parser: Any) -> list[PermissionInfo]:
    """Extract and deterministically sort permissions requested by the APK."""

    method = getattr(parser, "get_permissions", None)
    if not callable(method):
        return []
    try:
        permissions = method() or []
    except Exception:
        return []
    names = sorted({str(permission) for permission in permissions})
    return [PermissionInfo(name=name, category=classify_permission(name)) for name in names]
