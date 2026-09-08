"""Offline URL and domain extraction from APK string-bearing archive members."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .models import NetworkInfo
from .resources import TextSource

_URL_PATTERN = re.compile(
    r"https?://[A-Za-z0-9][A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*",
    flags=re.IGNORECASE,
)
_TRAILING_URL_PUNCTUATION = ".,;:!?)]}>"
_SENSITIVE_QUERY_NAMES = re.compile(
    r"(?:api[_-]?key|token|secret|password|passwd|credential|auth)", re.IGNORECASE
)


def _redact_url_query(url: str) -> str:
    """Keep endpoint evidence while redacting credential-like query values."""

    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    if not query:
        return url
    safe_query = [
        (name, "REDACTED" if _SENSITIVE_QUERY_NAMES.search(name) else value)
        for name, value in query
    ]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(safe_query), ""))


def _normalize_url(candidate: str) -> tuple[str, str] | None:
    """Return a normalized, safe URL and lower-cased domain if valid."""

    candidate = candidate.rstrip(_TRAILING_URL_PUNCTUATION)
    parts = urlsplit(candidate)
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        return None
    hostname = parts.hostname.lower()
    try:
        port_number = parts.port
    except ValueError:
        return None
    port = f":{port_number}" if port_number is not None else ""
    netloc = f"{hostname}{port}"
    normalized = urlunsplit(
        (parts.scheme.lower(), netloc, parts.path, parts.query, "")
    )
    if _is_xml_namespace(normalized, hostname):
        return None
    return _redact_url_query(normalized), hostname


def _is_xml_namespace(url: str, hostname: str) -> bool:
    """Exclude Android/XML namespace identifiers that are not endpoints."""

    path = urlsplit(url).path
    return (hostname == "schemas.android.com") or (
        hostname == "www.w3.org" and path.startswith("/2000/")
    )


def extract_network_info(sources: list[TextSource]) -> NetworkInfo:
    """Extract deterministic URL and domain lists without accessing endpoints."""

    discovered: set[tuple[str, str]] = set()
    for source in sources:
        for match in _URL_PATTERN.finditer(source.text):
            normalized = _normalize_url(match.group(0))
            if normalized is not None:
                discovered.add(normalized)

    urls = sorted(url for url, _ in discovered)
    domains = sorted({domain for _, domain in discovered})
    return NetworkInfo(
        urls=urls,
        domains=domains,
        http_urls=[url for url in urls if url.startswith("http://")],
        https_urls=[url for url in urls if url.startswith("https://")],
    )
