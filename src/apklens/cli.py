"""Command-line interface for APKLens."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from . import __version__
from .analyzer import APKAnalyzer
from .apk import APKLensError
from .report import JSONReporter, TerminalReporter


def build_parser() -> argparse.ArgumentParser:
    """Build the APKLens argument parser."""

    parser = argparse.ArgumentParser(
        prog="apklens",
        description="Inspect an Android APK with lightweight static analysis.",
    )
    parser.add_argument("apk", nargs="?", metavar="APK", help="path to the APK file")
    parser.add_argument(
        "--json", action="store_true", help="write the analysis result as JSON"
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process-compatible exit status."""

    parser = build_parser()
    arguments = parser.parse_args(argv)
    if arguments.apk is None:
        parser.error("the following arguments are required: APK")

    try:
        result = APKAnalyzer(arguments.apk).analyze()
    except APKLensError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"Error: unable to read APK: {error}", file=sys.stderr)
        return 1

    reporter = JSONReporter(result) if arguments.json else TerminalReporter(result)
    print(reporter.render())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
