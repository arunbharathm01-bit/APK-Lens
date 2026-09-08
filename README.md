# APKLens

APKLens is a small, extensible command-line tool for **static Android APK
analysis**. It inspects an APK locally, normalizes the results into a stable
data model, and produces a readable terminal report or script-friendly JSON.
It never executes app code, contacts extracted URLs, uploads APKs, or runs
native libraries.

v0.2 answers both *what is inside this APK?* and *which static indicators may
merit a security review?* It is not a complete mobile security assessment.

## Installation

APKLens requires Python 3.11 or later.

```bash
pip install -e .
```

For development and tests:

```bash
pip install -e ".[dev]"
pytest
```

## Usage

```bash
apklens app.apk
apklens app.apk --json
apklens app.apk --json | jq
apklens --version
apklens --help
```

`--json` writes only JSON to standard output. Errors are written to standard
error, so it remains safe to use in scripts. APKLens also handles an early
downstream close such as `apklens app.apk --json | head` without a traceback.

## What v0.2 inspects

- v0.1 APK metadata, manifest components, permissions, DEX statistics, and
  native library inventory
- URLs, unique domains, HTTP endpoints, and HTTPS endpoints found in selected
  archive resources and DEX string data
- `android:usesCleartextTraffic`, represented as explicitly enabled, explicitly
  disabled, not declared, or unknown
- DEX references to runtime execution, dynamic class loading, reflection,
  WebView, and cryptographic APIs
- Explicit string evidence for selected WebView settings such as
  `setJavaScriptEnabled(true)`
- Conservative hardcoded-secret patterns: private-key headers, GitHub tokens,
  AWS credentials, JWT-shaped values, and non-placeholder credential
  assignments
- Android/system versus application-defined permissions, with a small
  conservative normal/dangerous/special classification
- Signing certificate subject, issuer, serial number, SHA-256 fingerprint,
  validity period, available signature schemes, and Android debug certificate
  evidence
- Stable, evidence-backed findings plus an explainable risk-prioritisation
  score

## Findings and confidence

Every finding has a stable detector ID, category, severity, confidence,
description, evidence, location where available, and remediation guidance.
Examples include `APK-MANIFEST-001`, `APK-NET-001`, `APK-WEBVIEW-001`,
`APK-SECRET-002`, and `APK-SIGN-001`.

Severity is an analyst-prioritisation level (`INFO`, `LOW`, `MEDIUM`, `HIGH`).
Confidence (`LOW`, `MEDIUM`, `HIGH`) describes how directly the static evidence
supports that specific observation. An API reference is an indicator, not a
vulnerability: APKLens deliberately does not call `WebView`, `Cipher`, or
`DexClassLoader` use insecure by itself.

Credential-like evidence is always redacted in terminal and JSON reports. URL
query values for credential-like parameter names are also replaced with
`REDACTED`.

## Risk score

The 0–100 risk score is deterministic and explainable. It is a way to order
review work, not a claim that an APK is exploitable or safe.

| Severity | Base points |
| --- | ---: |
| INFO | 0 |
| LOW | 5 |
| MEDIUM | 10 |
| HIGH | 20 |

Confidence scales the base by `LOW=0.4`, `MEDIUM=0.7`, or `HIGH=1.0`, rounded
to the nearest point. Individual contributors are shown in both reports; the
final score is capped at 100. For example, an explicit cleartext setting is
`MEDIUM/HIGH` (+10), an exported component without an explicit permission is
`MEDIUM/MEDIUM` (+7), and an enabled debuggable flag is `LOW/HIGH` (+5).

## JSON output

The JSON structure is stable and deterministic for v0.2:

```json
{
  "tool": {"name": "APKLens", "version": "0.2.0"},
  "apk": {},
  "application": {},
  "manifest": {},
  "permissions": [],
  "dex": {},
  "native": {},
  "network": {
    "urls": [],
    "domains": [],
    "http_urls": [],
    "https_urls": []
  },
  "indicators": [],
  "signing": {},
  "findings": [],
  "summary": {
    "risk_score": 0,
    "severity_counts": {},
    "contributions": []
  }
}
```

## Architecture

```text
CLI → APKAnalyzer → normalized AnalysisResult → TerminalReporter / JSONReporter
                    ├─ APK file + parser boundary
                    ├─ Manifest + permission analysis
                    ├─ DEX statistics + API indicators
                    ├─ Archive resource/string analysis
                    ├─ Network, WebView, secret, and signing detectors
                    └─ Findings → risk assessment
```

Third-party parser objects never escape into the public models. Detector logic
is separate from reporters, so the same analysis powers the terminal and JSON
formats.

## Limitations

- APKLens is static analysis, not a complete audit, decompiler, emulator, or
  dynamic instrumentation tool.
- URL and secret detectors inspect selected archive data only. Obfuscation,
  encryption, runtime-generated values, and data beyond the per-member scan
  limit can evade detection.
- DEX API indicators identify string descriptors and method-name references;
  they do not prove a method executed or reveal all call arguments.
- A referenced network-security configuration resource is recorded, but v0.2
  does not resolve every compiled network-security XML rule.
- Certificate extraction reports available package signing material. It does
  not validate trust chains or perform online revocation checks.
- No network requests are made at any point.

## Roadmap

```text
v0.1
  ✓ APK metadata and manifest analysis
  ✓ Permissions, DEX statistics, native library detection
  ✓ Basic security findings and JSON output

v0.2
  ✓ Stable findings with severity, confidence, evidence, and IDs
  ✓ URL/domain and cleartext-traffic analysis
  ✓ DEX API indicators and conservative WebView checks
  ✓ Redaction-first secret detection
  ✓ Permission intelligence and signing certificate metadata
  ✓ Explainable risk score and improved reports

Future
  - Deep bytecode/data-flow analysis
  - Dangerous API call-argument analysis
  - Full network-security resource resolution
  - Certificate trust-chain analysis
  - Native ELF analysis
  - HTML reports
  - Plugin architecture
```
