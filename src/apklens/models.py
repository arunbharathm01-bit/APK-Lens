"""Normalized, JSON-serializable data models used by APKLens."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(slots=True)
class APKInfo:
    """File-level metadata for an APK archive."""

    filename: str = ""
    size_bytes: int = 0
    sha256: str = ""


@dataclass(slots=True)
class ApplicationInfo:
    """Metadata declared for the Android application."""

    package_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    min_sdk: str | None = None
    target_sdk: str | None = None
    debuggable: bool = False
    allow_backup: bool | None = None
    backup_agent: str | None = None
    full_backup_content: str | None = None
    data_extraction_rules: str | None = None


@dataclass(slots=True)
class ComponentInfo:
    """A declared Android component, with its relevant manifest attributes."""

    name: str = ""
    exported: bool | None = None
    exported_source: str = "unknown"
    permission: str | None = None
    enabled: bool | None = None


@dataclass(slots=True)
class ManifestInfo:
    """Manifest components normalized by Android component type."""

    activities: list[ComponentInfo] = field(default_factory=list)
    services: list[ComponentInfo] = field(default_factory=list)
    receivers: list[ComponentInfo] = field(default_factory=list)
    providers: list[ComponentInfo] = field(default_factory=list)

    @property
    def components(self) -> tuple[tuple[str, ComponentInfo], ...]:
        """Return all components paired with their type in deterministic order."""

        groups = (
            ("activity", self.activities),
            ("service", self.services),
            ("receiver", self.receivers),
            ("provider", self.providers),
        )
        return tuple((kind, component) for kind, items in groups for component in items)


@dataclass(slots=True)
class PermissionInfo:
    """A permission requested by the application."""

    name: str = ""
    category: str | None = None


@dataclass(slots=True)
class DexInfo:
    """Lightweight statistics for DEX files packaged in the APK."""

    file_count: int = 0
    total_size_bytes: int = 0
    class_count: int | None = None


@dataclass(slots=True)
class NativeLibrary:
    """A shared library packaged under ``lib/<ABI>/``."""

    abi: str = ""
    filename: str = ""
    size_bytes: int = 0


@dataclass(slots=True)
class NativeLibraryInfo:
    """Native shared libraries discovered in the APK archive."""

    libraries: list[NativeLibrary] = field(default_factory=list)

    def counts_by_abi(self) -> dict[str, int]:
        """Return the number of shared libraries for each ABI."""

        counts: dict[str, int] = {}
        for library in self.libraries:
            counts[library.abi] = counts.get(library.abi, 0) + 1
        return dict(sorted(counts.items()))


@dataclass(slots=True)
class SecurityFinding:
    """A deterministic static-analysis observation."""

    severity: str = "INFO"
    title: str = ""
    reason: str = ""
    component_type: str | None = None
    component_name: str | None = None


@dataclass(slots=True)
class AnalysisResult:
    """Complete normalized result produced by :class:`APKAnalyzer`."""

    apk: APKInfo = field(default_factory=APKInfo)
    application: ApplicationInfo = field(default_factory=ApplicationInfo)
    manifest: ManifestInfo = field(default_factory=ManifestInfo)
    permissions: list[PermissionInfo] = field(default_factory=list)
    dex: DexInfo = field(default_factory=DexInfo)
    native: NativeLibraryInfo = field(default_factory=NativeLibraryInfo)
    findings: list[SecurityFinding] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """Return a recursively JSON-compatible representation of this result."""

        return asdict(self)
