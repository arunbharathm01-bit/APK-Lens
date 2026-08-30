"""Lightweight DEX archive inspection."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from zipfile import ZipFile

from .models import DexInfo


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
