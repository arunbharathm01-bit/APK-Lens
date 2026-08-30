"""Native library discovery from APK ZIP members."""

from __future__ import annotations

from pathlib import Path, PurePosixPath
from zipfile import ZipFile

from .models import NativeLibrary, NativeLibraryInfo


def native_library_from_path(member_name: str, size_bytes: int) -> NativeLibrary | None:
    """Create a native library record for a ``lib/<ABI>/*.so`` ZIP member."""

    member_path = PurePosixPath(member_name)
    parts = member_path.parts
    if len(parts) != 3 or parts[0] != "lib" or not parts[2].endswith(".so"):
        return None
    return NativeLibrary(abi=parts[1], filename=parts[2], size_bytes=size_bytes)


def extract_native_libraries(path: str | Path) -> NativeLibraryInfo:
    """Discover native shared objects stored in an APK archive."""

    libraries: list[NativeLibrary] = []
    with ZipFile(path) as archive:
        for entry in archive.infolist():
            library = native_library_from_path(entry.filename, entry.file_size)
            if library is not None:
                libraries.append(library)
    libraries.sort(key=lambda library: (library.abi, library.filename))
    return NativeLibraryInfo(libraries=libraries)
