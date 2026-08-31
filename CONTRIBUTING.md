# Contributing to APKLens

Thank you for your interest in contributing to **APKLens**.

APKLens is an open-source static analysis CLI for Android APKs. Contributions are welcome from developers, students, security enthusiasts, Android developers, and anyone interested in learning through open-source development.

You do not need to be an expert to contribute.

## Ways to Contribute

You can contribute through:

* Bug fixes
* New APK analysis features
* Security checks
* Manifest analysis improvements
* DEX analysis
* Native library analysis
* Test cases
* Documentation
* README improvements
* Performance improvements
* CLI improvements
* Ideas and feature discussions

Small contributions are welcome too.

## Before You Start

For larger changes, open an issue first to discuss the idea.

For small fixes such as documentation changes, tests, or obvious bugs, you can open a pull request directly.

Please check existing issues and pull requests before starting work to avoid duplicated effort.

## Development Setup

APKLens requires **Python 3.11+**.

Clone the repository:

```bash
git clone https://github.com/arunbharathm01-bit/APK-Lens.git
cd APK-Lens
```

Create a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

Install the project in editable mode:

```bash
pip install -e ".[dev]"
```

Run the tests:

```bash
pytest
```

Run APKLens locally:

```bash
apklens path/to/app.apk
```

For JSON output:

```bash
apklens path/to/app.apk --json
```

## Project Structure

```text
src/apklens/
├── cli.py
├── analyzer.py
├── models.py
├── apk.py
├── manifest.py
├── dex.py
├── native.py
├── security.py
└── report.py
```

The main architecture is:

```text
APK
 ↓
Parser / Analysis
 ↓
AnalysisResult
 ↓
Reporter
 ├── Terminal
 └── JSON
```

Keep this separation intact when adding features.

Analysis code should produce normalized data rather than coupling directly to terminal or JSON output.

## Code Guidelines

Please aim for:

* Clear and readable Python
* Type hints
* Small, focused functions
* Meaningful names
* Minimal dependencies
* Deterministic output
* Appropriate error handling
* Tests for new functionality

Avoid unnecessary refactoring unrelated to your change.

## Adding Security Findings

Security findings should be conservative and evidence-based.

Do not label something a vulnerability simply because it may be interesting.

Whenever possible, explain:

```text
What was detected
Why it may matter
What evidence was found
```

Avoid false positives and exaggerated severity.

APKLens is a static analysis tool, not a replacement for a complete security assessment.

## Pull Requests

Before opening a pull request:

1. Make sure the project installs successfully.
2. Run `pytest`.
3. Check that your changes do not introduce unnecessary dependencies.
4. Update documentation when appropriate.
5. Keep the pull request focused on one change or closely related changes.
6. Provide a clear description of what changed and why.

A useful pull request description includes:

```text
## What changed

Briefly describe the change.

## Why

Explain the reason for the change.

## Testing

Explain how the change was tested.
```

## Commit Messages

Use concise commit messages that describe the change.

Examples:

```text
add exported component detection
fix APK hash calculation
improve permission classification
add native library tests
update installation documentation
```

## Student Contributions

Students are welcome to contribute.

You do not need professional development experience to participate.

If you are learning Python, Android internals, cybersecurity, reverse engineering, testing, or open-source development, APKLens can be a practical project to learn from.

If you are unsure whether an idea is suitable, open an issue or contact the project maintainer before implementing it.

## Questions and Ideas

If you have an idea, find a bug, or want to discuss contributing, open an issue on GitHub.

For contribution-related questions, you can also contact the project maintainer directly.

## Code of Conduct

Please be respectful and constructive when interacting with other contributors.

Harassment, discrimination, personal attacks, and intentionally disruptive behavior are not welcome.

## License

By contributing to APKLens, you agree that your contributions will be licensed under the same **MIT License** that covers the project.

Thank you for helping improve APKLens.
