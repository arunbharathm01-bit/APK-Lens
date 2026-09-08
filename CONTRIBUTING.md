# Contributing to APKLens

APKLens is an offline static-analysis tool. Contributions should preserve that
property: never upload APK data, call extracted endpoints, execute APK code, or
expose a detected credential in output.

## Adding a detector

Keep detectors focused in an appropriate module rather than adding unrelated
logic to the analyzer or reporter. Use the strongest source available:

- manifest configuration for manifest observations;
- DEX descriptors/method references for code indicators;
- selected archive resources for string-oriented evidence;
- signing metadata for certificate observations.

Raw string matching is appropriate for URLs and high-signal credential
patterns, but not as a substitute for a more direct Android source.

Every finding must have a stable `APK-<AREA>-<NUMBER>` ID, a severity,
confidence, category, concise evidence, a careful description, and remediation
when practical. Avoid calling an indicator a vulnerability without evidence.

## Secret-handling rules

Never put a full suspected credential in a finding, terminal report, JSON test
fixture, assertion failure, or documentation example. Use the shared redaction
helper and test that raw values are absent from reports.

## Tests

Add parser-independent fixtures or mocks whenever possible. Every detector
needs a positive case, a negative case, and an edge case (for example duplicate,
malformed, or placeholder input). Tests must not download APKs or contact the
network.

Run the complete suite before opening a change:

```bash
pytest
```
