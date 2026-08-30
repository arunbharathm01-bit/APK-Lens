# APKLens

APKLens is a small, extensible command-line tool for **static APK analysis**.
It inspects an Android APK directly, extracts useful package and manifest
metadata, and produces either a readable terminal report or script-friendly
JSON. It never executes application code, uploads APKs, or performs network
scanning.

## Why APKLens?

APK inspection is often the first step in understanding an Android package.
APKLens keeps that step quick and transparent: it provides a clean baseline
for metadata inspection and a few careful static observations without claiming
to be a complete security audit.

## Installation

APKLens requires Python 3.11 or later.

```bash
pip install -e .
```

For the test dependencies:

```bash
pip install -e ".[dev]"
pytest
```

## Usage

```bash
apklens app.apk
apklens app.apk --json
apklens --version
apklens --help
```

JSON mode writes only JSON to standard output, making it suitable for tools
such as `jq`:

```bash
apklens app.apk --json | jq '.application.package_name'
```

Example terminal output:

```text
APKLens v0.1.0
────────────────────────────────────────

APK
  File          app.apk
  Size          47.8 MB
  SHA-256       3f...e9

Application
  Package       com.example.app
  Version       1.4.2
  Version Code  42
  Min SDK       26
  Target SDK    35

Manifest
  Activities       14
  Services          5
  Receivers         8
  Providers         2
```

## What v0.1 inspects

- APK filename, size, and streaming SHA-256 hash
- Package/version/SDK metadata
- Manifest activities, services, receivers, and providers
- Requested permissions with a small conservative category set
- DEX file count, uncompressed DEX size, and class count when available
- Native shared libraries under `lib/<ABI>/*.so`
- Basic static observations: debuggable state, unprotected exported
  components, and declared backup configuration

`android:exported` is represented with both a value and its source. When the
attribute is absent, APKLens applies only known Android defaults (such as the
intent-filter rule for activities/services/receivers); otherwise it reports the
state as unknown rather than guessing.

## Architecture

```text
CLI → APKAnalyzer → normalized AnalysisResult → TerminalReporter / JSONReporter
                  ├─ APK file and parser boundary
                  ├─ manifest + permissions
                  ├─ DEX archive inspection
                  ├─ native library inspection
                  └─ deterministic security checks
```

The models never expose `androguard` objects. This keeps reporting and most
unit tests independent of the parser, while the parser boundary remains easy
to extend.

## Current limitations

APKLens is not a full security scanner. v0.1 does not analyze bytecode flows,
certificates, URLs, secrets, APIs, or ELF binaries. The small findings set is
informational and should be reviewed in the context of the app.

## Roadmap

```text
v0.1
  ✓ APK metadata
  ✓ Manifest analysis
  ✓ Permissions
  ✓ Basic DEX statistics
  ✓ Native library detection
  ✓ Basic security findings
  ✓ JSON output

Future
  - Deep DEX analysis
  - Dangerous API detection
  - URL/domain extraction
  - Certificate/signature analysis
  - Hardcoded secret detection
  - Native ELF analysis
  - HTML reports
  - Risk scoring
  - Plugin architecture
```
