"""Lightweight DEX archive inspection."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from zipfile import ZipFile

from .models import APIIndicator, DexInfo


def _is_dex_filename(name: str) -> bool:
    """Return whether a ZIP member is a conventional top-level DEX file."""

    if "/" in name or not name.endswith(".dex"):
        return False
    stem = name.removesuffix(".dex")
    return stem == "classes" or (stem.startswith("classes") and stem[7:].isdigit())


def _count_classes(parser: Any) -> int | None:
    """Ask androguard for class counts when its DEX interface is available."""

    get_all_dex = getattr(parser, "get_all_dex", None)
    if not callable(get_all_dex):
        return None
    try:
        from androguard.core.dex import DEX

        count = 0
        for raw_dex in get_all_dex():
            dex = DEX(raw_dex)
            count += sum(1 for _ in dex.get_classes())
        return count
    except Exception:
        # The archive is still useful if one optional DEX parser feature fails.
        return None


def extract_dex_info(path: str | Path, parser: Any | None = None) -> DexInfo:
    """Return DEX file count, uncompressed total size, and optional class count."""

    with ZipFile(path) as archive:
        dex_entries = sorted(
            (entry for entry in archive.infolist() if _is_dex_filename(entry.filename)),
            key=lambda entry: entry.filename,
        )
    return DexInfo(
        file_count=len(dex_entries),
        total_size_bytes=sum(entry.file_size for entry in dex_entries),
        class_count=_count_classes(parser) if parser is not None else None,
    )


_API_INDICATORS: tuple[tuple[str, str, bytes], ...] = (
    ("runtime_execution", "java.lang.Runtime", b"Ljava/lang/Runtime;"),
    ("runtime_execution", "ProcessBuilder", b"Ljava/lang/ProcessBuilder;"),
    ("dynamic_loading", "DexClassLoader", b"Ldalvik/system/DexClassLoader;"),
    ("dynamic_loading", "PathClassLoader", b"Ldalvik/system/PathClassLoader;"),
    ("reflection", "java.lang.reflect", b"Ljava/lang/reflect/"),
    ("webview", "WebView", b"Landroid/webkit/WebView;"),
    ("webview", "setJavaScriptEnabled", b"setJavaScriptEnabled"),
    ("webview", "addJavascriptInterface", b"addJavascriptInterface"),
    ("webview", "setAllowFileAccess", b"setAllowFileAccess"),
    (
        "webview",
        "setAllowUniversalAccessFromFileURLs",
        b"setAllowUniversalAccessFromFileURLs",
    ),
    ("cryptography", "Cipher", b"Ljavax/crypto/Cipher;"),
    ("cryptography", "MessageDigest", b"Ljava/security/MessageDigest;"),
    ("cryptography", "SecretKeySpec", b"Ljavax/crypto/spec/SecretKeySpec;"),
)


def extract_api_indicators(path: str | Path) -> list[APIIndicator]:
    """Count security-relevant DEX descriptors and method-name references.

    DEX string identifiers are analysed directly, avoiding decompilation or
    execution. A reference demonstrates that code contains the named symbol,
    not that the sensitive behaviour necessarily occurs at runtime.
    """

    counts: dict[tuple[str, str], int] = {}
    locations: dict[tuple[str, str], set[str]] = {}
    with ZipFile(path) as archive:
        dex_entries = sorted(
            (entry for entry in archive.infolist() if _is_dex_filename(entry.filename)),
            key=lambda entry: entry.filename,
        )
        for entry in dex_entries:
            content = archive.read(entry)
            for category, indicator, marker in _API_INDICATORS:
                references = content.count(marker)
                if references:
                    key = (category, indicator)
                    counts[key] = counts.get(key, 0) + references
                    locations.setdefault(key, set()).add(entry.filename)
    return [
        APIIndicator(
            category=category,
            indicator=indicator,
            references=counts[(category, indicator)],
            locations=sorted(locations[(category, indicator)]),
        )
        for category, indicator in sorted(counts)
    ]
