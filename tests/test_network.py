"""Tests for offline URL and domain analysis."""

from __future__ import annotations

from pathlib import Path
from zipfile import ZipFile

from apklens.network import extract_network_info
from apklens.resources import extract_text_sources


def test_extracts_deduplicated_urls_domains_and_http_endpoints(tmp_path: Path) -> None:
    apk_path = tmp_path / "network.apk"
    with ZipFile(apk_path, "w") as archive:
        archive.writestr(
            "assets/config.txt",
            b"https://API.example.com/v1?token=super-secret-token http://cdn.example.com/a",
        )
        archive.writestr("classes.dex", b"https://api.example.com/v1?token=super-secret-token")

    network = extract_network_info(extract_text_sources(apk_path))

    assert network.urls == [
        "http://cdn.example.com/a",
        "https://api.example.com/v1?token=REDACTED",
    ]
    assert network.domains == ["api.example.com", "cdn.example.com"]
    assert network.http_urls == ["http://cdn.example.com/a"]
    assert network.https_urls == ["https://api.example.com/v1?token=REDACTED"]
    assert "super-secret-token" not in "\n".join(network.urls)


def test_ignores_invalid_urls_without_failing_analysis(tmp_path: Path) -> None:
    apk_path = tmp_path / "invalid-network.apk"
    with ZipFile(apk_path, "w") as archive:
        archive.writestr("assets/config.txt", "http://example.com:bad-port https://valid.example/path")

    network = extract_network_info(extract_text_sources(apk_path))
    assert network.urls == ["https://valid.example/path"]


def test_ignores_binary_resource_tails_and_xml_namespace_identifiers(tmp_path: Path) -> None:
    apk_path = tmp_path / "compiled-resource.apk"
    with ZipFile(apk_path, "w") as archive:
        archive.writestr(
            "resources.arsc",
            b"http://schemas.android.com/apk/res/android\x00\xffjunk"
            b"https://api.example.com/v2\x00trailing-binary",
        )

    network = extract_network_info(extract_text_sources(apk_path))
    assert network.urls == ["https://api.example.com/v2"]
