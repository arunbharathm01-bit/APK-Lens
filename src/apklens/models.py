"""Normalized, JSON-serializable data models used by APKLens."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Impact level assigned to an evidence-backed security finding."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Confidence(str, Enum):
    """Confidence that a finding's evidence supports its conclusion."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class CleartextTrafficState(str, Enum):
    """How ``android:usesCleartextTraffic`` is represented in a manifest."""

    ENABLED = "explicitly_enabled"
    DISABLED = "explicitly_disabled"
    NOT_DECLARED = "not_declared"
    UNKNOWN = "unknown"


class PermissionScope(str, Enum):
    """Whether a permission belongs to Android or the analysed application."""

    ANDROID = "android_system"
    APPLICATION = "application_defined"
    UNKNOWN = "unknown"


class PermissionProtection(str, Enum):
    """A small, conservative protection-level classification."""

    NORMAL = "normal"
    DANGEROUS = "dangerous"
    SPECIAL = "special_or_restricted"
    UNKNOWN = "unknown"


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
    cleartext_traffic: CleartextTrafficState = CleartextTrafficState.NOT_DECLARED
    network_security_config: str | None = None


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
    scope: PermissionScope = PermissionScope.UNKNOWN
    protection_level: PermissionProtection = PermissionProtection.UNKNOWN


@dataclass(slots=True)
class DexInfo:
    """Lightweight statistics for DEX files packaged in the APK."""

    file_count: int = 0
    total_size_bytes: int = 0
    class_count: int | None = None


@dataclass(slots=True)
class APIIndicator:
    """A static reference to an API that merits analyst attention."""

    category: str = ""
    indicator: str = ""
    references: int = 0
    locations: list[str] = field(default_factory=list)


@dataclass(slots=True)
class NetworkInfo:
    """Network endpoints statically observed in APK resources or DEX data."""

    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    http_urls: list[str] = field(default_factory=list)
    https_urls: list[str] = field(default_factory=list)


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
class SigningCertificate:
    """Normalized metadata for one signing certificate."""

    subject: str = ""
    issuer: str = ""
    serial_number: str = ""
    sha256_fingerprint: str = ""
    valid_from: str | None = None
    valid_until: str | None = None


@dataclass(slots=True)
class SigningInfo:
    """Certificates and signature schemes discovered in an APK."""

    certificates: list[SigningCertificate] = field(default_factory=list)
    signature_schemes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class SecurityFinding:
    """A stable, evidence-backed result from one static detector."""

    id: str = ""
    title: str = ""
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.LOW
    category: str = ""
    description: str = ""
    evidence: str | None = None
    location: str | None = None
    component_type: str | None = None
    component_name: str | None = None
    remediation: str | None = None

    @property
    def reason(self) -> str:
        """Compatibility alias for the v0.1 finding description field."""

        return self.description


@dataclass(slots=True)
class RiskContribution:
    """One finding's explainable contribution to the risk score."""

    points: int = 0
    finding_id: str = ""
    title: str = ""


@dataclass(slots=True)
class AnalysisSummary:
    """Deterministic, bounded risk assessment derived from findings."""

    risk_score: int = 0
    severity_counts: dict[str, int] = field(
        default_factory=lambda: {severity.value: 0 for severity in Severity}
    )
    contributions: list[RiskContribution] = field(default_factory=list)


@dataclass(slots=True)
class AnalysisResult:
    """Complete normalized result produced by :class:`APKAnalyzer`."""

    apk: APKInfo = field(default_factory=APKInfo)
    application: ApplicationInfo = field(default_factory=ApplicationInfo)
    manifest: ManifestInfo = field(default_factory=ManifestInfo)
    permissions: list[PermissionInfo] = field(default_factory=list)
    dex: DexInfo = field(default_factory=DexInfo)
    native: NativeLibraryInfo = field(default_factory=NativeLibraryInfo)
    network: NetworkInfo = field(default_factory=NetworkInfo)
    indicators: list[APIIndicator] = field(default_factory=list)
    signing: SigningInfo = field(default_factory=SigningInfo)
    findings: list[SecurityFinding] = field(default_factory=list)
    summary: AnalysisSummary = field(default_factory=AnalysisSummary)

    def to_dict(self) -> dict[str, object]:
        """Return a recursively JSON-compatible representation of this result."""

        from .version import __version__

        return {
            "tool": {"name": "APKLens", "version": __version__},
            **asdict(self),
        }
