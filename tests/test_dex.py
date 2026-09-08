"""Tests for DEX API reference indicators."""

from __future__ import annotations

from pathlib import Path
from zipfile import ZipFile

from apklens.dex import extract_api_indicators


def test_extracts_security_relevant_dex_indicators(tmp_path: Path) -> None:
    apk_path = tmp_path / "indicators.apk"
    with ZipFile(apk_path, "w") as archive:
        archive.writestr(
            "classes.dex",
            b"Ljava/lang/Runtime;Ldalvik/system/DexClassLoader;Landroid/webkit/WebView;"
            b"setJavaScriptEnabledsetJavaScriptEnabled",
        )

    indicators = extract_api_indicators(apk_path)
    assert [(item.category, item.indicator, item.references) for item in indicators] == [
        ("dynamic_loading", "DexClassLoader", 1),
        ("runtime_execution", "java.lang.Runtime", 1),
        ("webview", "WebView", 1),
        ("webview", "setJavaScriptEnabled", 2),
    ]
    assert all(item.locations == ["classes.dex"] for item in indicators)


def test_ignores_unrelated_dex_content(tmp_path: Path) -> None:
    apk_path = tmp_path / "empty-indicators.apk"
    with ZipFile(apk_path, "w") as archive:
        archive.writestr("classes.dex", b"ordinary application strings")

    assert extract_api_indicators(apk_path) == []
