# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-05-13

Initial public release. CodeSentinel is functional end-to-end as a security
scanner for source repositories, with 202 tests covering the Core, Application,
Infrastructure, and CLI layers.

### Added

#### Detection engine
- Twelve built-in detection rules covering common secrets and insecure patterns:
  - `CS001` AWS access key IDs (`AKIA…`, `ASIA…`)
  - `CS002` AWS secret access keys in assignment expressions
  - `CS003` PEM private key headers (RSA, EC, OpenSSH, DSA, PGP)
  - `CS004` JSON Web Tokens
  - `CS005` Hardcoded credentials (`password`, `secret`, `api_key`, …)
  - `CS006` GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`)
  - `CS007` Slack tokens (`xoxb-`, `xoxp-`, `xapp-`, …)
  - `CS008` Stripe secret and restricted API keys
  - `CS009` Google API keys (`AIza…`)
  - `CS010` npm registry access tokens (`npm_…`)
  - `CS101` Weak hash algorithms — MD5/SHA-1 in .NET, Python, Java
  - `CS900` Shannon-entropy heuristic for high-entropy strings
- Secret-category rules redact matched values in report snippets so raw
  credentials never appear in output.
- 0–100 security score with letter grade (A–F) computed from severity-weighted
  penalties (Critical 25, High 15, Medium 8, Low 3, Info 1).
- Pluggable architecture: `IDetectionRule`, `IFileSource`, `IRuleProvider`,
  `ISecurityScorePolicy`.

#### Reporting
- JSON report writer (machine-readable, findings sorted by severity).
- HTML report writer (self-contained, embedded CSS, all user-controlled
  content HTML-escaped to prevent XSS).
- SARIF v2.1.0 report writer for GitHub Code Scanning integration.
- `IReportService` dispatches by format; new writers register via DI.

#### CLI
- Scan local directories or remote Git repositories (HTTPS, SSH, git://).
  Remote repositories are cloned to a temporary directory, scanned, and the
  clone is removed on exit.
- `--format` / `-f`, `--output` / `-o`, with extension inference
  (`.json` / `.html` / `.htm` / `.sarif`).
- `--fail-on <severity>` threshold for CI/CD exit-code control.
- `--exclude` / `-e` (repeatable) glob exclusions combined with patterns
  from `.codesentinelignore` in the scan root.
- `--verbose` / `-v` and `--quiet` / `-q` log-level switches.
- `--version` and `--help` via System.CommandLine `UseDefaults()`.
- `list-rules` subcommand prints a table of every registered rule.
- Deterministic exit codes (`0` clean, `1` findings, `2` scan error).

#### Distribution
- Packaged as a .NET global tool — install with
  `dotnet tool install --global --add-source ./artifacts/nupkg CodeSentinel.Cli`.
- Multi-stage `Dockerfile` using `mcr.microsoft.com/dotnet/runtime-deps:8.0-jammy-chiseled`
  for a distroless runtime image.
- Two GitHub Actions workflows:
  - `build.yml` — cross-platform restore, build, and test on Linux, Windows, macOS.
  - `security.yml` — self-scan that publishes SARIF to the repository's Security tab.

#### Project meta
- MIT License.
- README with quick start, CLI reference, rule table, sample output, and
  architecture overview.
- Single source of truth for the project URL in `Directory.Build.props`,
  surfaced as MSBuild property and as runtime assembly metadata.

[Unreleased]: https://github.com/Carlosmarroquin20/CodeSentinel/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Carlosmarroquin20/CodeSentinel/releases/tag/v0.1.0
