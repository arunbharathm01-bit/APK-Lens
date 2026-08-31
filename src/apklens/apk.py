"""APK file validation, hashing, and parser loading utilities."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from typing import Any
from zipfile import BadZipFile, ZipFile

from .models import APKInfo


class APKLensError(Exception):
    """Base exception for user-facing APKLens errors."""


class APKPathError(APKLensError):
    """Raised when an APK path cannot safely be read."""


class APKParseError(APKLensError):
    """Raised when an APK cannot be parsed as a valid Android package."""


def validate_apk_path(value: str | Path) -> Path:
    """Validate *value* as a readable regular file and return its path.

    The function intentionally does not require an ``.apk`` suffix: some valid
    APK artifacts have extensionless temporary names.
    """

    path = Path(value).expanduser()
    if not path.exists():
        raise APKPathError(f"APK file not found: {path}")
    if not path.is_file():
        raise APKPathError(f"APK path is not a file: {path}")
    try:
        with path.open("rb"):
            pass
    except OSError as error:
        raise APKPathError(f"APK file is not readable: {path}") from error
    return path


def calculate_sha256(path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    """Calculate the SHA-256 digest of a file using bounded memory."""

    digest = sha256()
    with Path(path).open("rb") as apk_file:
        while chunk := apk_file.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def extract_apk_info(path: str | Path) -> APKInfo:
    """Extract filesystem metadata for a validated APK file."""

    apk_path = Path(path)
    return APKInfo(
        filename=apk_path.name,
        size_bytes=apk_path.stat().st_size,
        sha256=calculate_sha256(apk_path),
    )


def open_apk_archive(path: str | Path) -> ZipFile:
    """Open an APK as a ZIP archive, translating corrupt archive errors."""

    try:
        return ZipFile(path)
    except (BadZipFile, OSError) as error:
        raise APKParseError(f"Invalid or corrupt APK archive: {path}") from error


def load_apk_parser(path: str | Path) -> Any:
    """Load an APK using androguard without leaking its object outside this module."""

    try:
        from androguard.core.apk import APK
    except ImportError as error:  # Helpful when using source without installing deps.
        raise APKParseError(
            "Androguard is required for manifest analysis. Install APKLens dependencies first."
        ) from error

    # Androguard enables a verbose Loguru handler by default. Its diagnostics
    # are useful while developing Androguard itself, but they obscure APKLens'
    # user-facing error messages (and would be especially surprising in JSON
    # mode). The parser's exceptions are normalized below instead.
    try:
        from loguru import logger

        logger.disable("androguard")
    except ImportError:
        # Loguru is an Androguard dependency, but keeping this defensive makes
        # the parser boundary robust to alternate parser installations.
        pass

    try:
        parser = APK(str(path))
        is_valid = getattr(parser, "is_valid_APK", None)
        if callable(is_valid) and not is_valid():
            raise APKParseError(f"Invalid Android APK: {path}")
        return parser
    except APKParseError:
        raise
    except Exception as error:
        raise APKParseError(f"Unable to parse APK: {path}") from error
