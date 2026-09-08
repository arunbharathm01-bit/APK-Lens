"""Safe extraction of selected APK archive data for static string analysis."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from zipfile import ZipFile

MAX_MEMBER_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class TextSource:
    """Text-like archive content together with its APK member location."""

    location: str
    text: str


def _is_scannable_member(member_name: str) -> bool:
    """Return whether an APK member can reasonably contain useful strings."""

    if member_name in {"AndroidManifest.xml", "resources.arsc"}:
        return True
    if member_name.startswith(("assets/", "res/")):
        return True
    if "/" not in member_name and member_name.endswith(".dex"):
        return True
    return False


def extract_text_sources(path: str | Path) -> list[TextSource]:
    """Read selected APK members for offline text-pattern detectors.

    Content is decoded with Latin-1 because it preserves ASCII strings embedded
    in DEX and compiled Android resources without discarding undecodable bytes.
    Per-member reads are capped to keep a malicious archive from consuming
    unbounded process memory; this is a scan limit, not an APK size limit.
    """

    sources: list[TextSource] = []
    with ZipFile(path) as archive:
        entries = sorted(archive.infolist(), key=lambda entry: entry.filename)
        for entry in entries:
            if entry.is_dir() or not _is_scannable_member(entry.filename):
                continue
            with archive.open(entry) as member:
                content = member.read(MAX_MEMBER_BYTES)
            if content:
                sources.append(
                    TextSource(location=entry.filename, text=content.decode("latin-1"))
                )
    return sources
