# CodeSentinel

[![build](https://github.com/Carlosmarroquin20/CodeSentinel/actions/workflows/build.yml/badge.svg)](https://github.com/Carlosmarroquin20/CodeSentinel/actions/workflows/build.yml)
[![security](https://github.com/Carlosmarroquin20/CodeSentinel/actions/workflows/security.yml/badge.svg)](https://github.com/Carlosmarroquin20/CodeSentinel/actions/workflows/security.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Security scanner for source code repositories. Detects exposed secrets, insecure
coding patterns, and misconfigurations — then assigns a security score so the
result is easy to act on in code review and CI/CD.

Built from scratch on .NET 8 with a clean, extensible architecture: rules are
plug-in components, file sources can be swapped (local paths and Git remotes),
and report writers compose freely (JSON, HTML, and SARIF).

## Status

MVP complete. Scanning engine, scoring, JSON/HTML/SARIF reporting, CLI surface,
Docker image, GitHub Actions integration, remote-repository support, and
distribution as a .NET global tool are all in place, with tests across the
Core, Application, Infrastructure, and CLI layers.

## What it detects

| Rule    | Category         | Severity   | Detects                                                          |
| ------- | ---------------- | ---------- | ---------------------------------------------------------------- |
| `CS001` | Secret           | Critical   | AWS access key IDs (`AKIA…`, `ASIA…`)                            |
| `CS002` | Secret           | Critical   | AWS secret access keys in assignment expressions                 |
| `CS003` | Secret           | Critical   | Private key headers (RSA, EC, OpenSSH, DSA, PKCS#8, OpenPGP)     |
| `CS004` | Secret           | High       | JSON Web Tokens                                                  |
| `CS005` | Secret           | High       | Hardcoded passwords, API keys, secrets, and tokens               |
| `CS006` | Secret           | Critical   | GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`) |
| `CS007` | Secret           | Critical   | Slack tokens (`xoxb-`, `xoxp-`, `xapp-`, …)                      |
| `CS008` | Secret           | Critical   | Stripe secret and restricted API keys (`sk_…`, `rk_…`)           |
| `CS009` | Secret           | High       | Google API keys (`AIza…`)                                        |
| `CS010` | Secret           | High       | npm registry access tokens (`npm_…`)                             |
| `CS101` | Insecure Pattern | Medium     | MD5 / SHA-1 usage (.NET, Python, Java)                           |
| `CS900` | Heuristic        | Medium     | High-entropy strings (Shannon entropy ≥ 4.5)                     |

Findings include severity, confidence, a redacted snippet, and the file path,
line and column span. Snippets in secret-category rules are redacted before they
reach the report — actual credentials never appear in output.

When several secret rules match the same characters (a GitHub token assigned to
a variable called `token` matches `CS006`, `CS005` and `CS900`), only the
highest-severity finding is kept, so one leak counts once. See
[ADR 0008](docs/adr/0008-consolidate-overlapping-secret-findings.md).

Text files are decoded as UTF-8, or as UTF-16/UTF-32 when they start with a
byte-order mark. Files over 1 MB, binary files and symbolic links are skipped;
links are never followed, so a committed link cannot pull files from outside
the repository into a report.

## Install

CodeSentinel ships as a .NET global tool. Pack the project and install from
the local NuGet output:

```sh
dotnet pack src/CodeSentinel.Cli -c Release
dotnet tool install --global --add-source ./artifacts/nupkg CodeSentinel.Cli
```

After installation the `codesentinel` command is available on `PATH`:

```sh
codesentinel --version
codesentinel list-rules
codesentinel /path/to/repo
```

To uninstall: `dotnet tool uninstall --global CodeSentinel.Cli`.

## Quick start

Using the installed tool:

```sh
# Scan a repository (console output only)
codesentinel /path/to/repo

# Generate an HTML report
codesentinel /path/to/repo -o report.html

# Generate a JSON report (for CI/CD)
codesentinel /path/to/repo -o report.json
```

Or run directly from source without installing:

```sh
dotnet run --project src/CodeSentinel.Cli -- /path/to/repo
```

Or scan the bundled fixture to see what a vulnerable repository looks like:

```sh
dotnet run --project src/CodeSentinel.Cli -- samples/vulnerable-repo -o report.html
```

### Scanning a remote repository

Pass a Git URL instead of a local path and CodeSentinel will clone the
repository into a temporary directory, scan it, and clean up after itself:

```sh
codesentinel https://github.com/octocat/Hello-World.git -o report.sarif
codesentinel git@github.com:owner/repo.git --fail-on High
```

Supported URL prefixes: `https://`, `http://`, `git://`, `ssh://`, `git@`.
For private repositories, ensure credentials are available to the local Git
configuration (SSH agent, credential helper, etc.).

## CLI reference

```
codesentinel <target> [--format <fmt>] [--output <file>] [--fail-on <severity>] [--exclude <glob>]
codesentinel list-rules
```

`<target>` is either a local directory or a Git remote URL — see
[Scanning a remote repository](#scanning-a-remote-repository) below.

### Subcommands

| Command       | Purpose                                                                |
| ------------- | ---------------------------------------------------------------------- |
| (no command)  | Scan the given repository path. This is the default behavior.          |
| `list-rules`  | Print a table of every detection rule currently registered.            |

### Scan options

| Flag              | Description                                                                                          |
| ----------------- | ---------------------------------------------------------------------------------------------------- |
| `<target>`        | Repository to scan (required). Local directory path **or** Git remote URL (https/ssh/git protocols).  |
| `--format`, `-f`  | Report format: `json`, `html`, or `sarif`. If omitted, inferred from `--output` extension; otherwise `json`. |
| `--output`, `-o`  | Path where the report will be written. If omitted, no file is created.                               |
| `--fail-on`       | Minimum severity (`Info`, `Low`, `Medium`, `High`, `Critical`) that triggers exit code 1. If omitted, any finding fails. The flag affects the exit code only — reports always include every finding. |
| `--exclude`, `-e` | Glob pattern to exclude from the scan. Repeatable. Combined with patterns from `.codesentinelignore` if present in the scan root. |
| `--no-inline-ignore` | Report findings even on lines marked with `codesentinel:ignore`. Use it together with `--no-ignore-file` for repositories you do not control. |
| `--no-ignore-file` | Do not read `.codesentinelignore` from the scan root. Use it when scanning repositories you do not control, since their ignore file could hide files. `--exclude` still applies. |
| `--verbose`, `-v` | Show debug-level log output, including per-file scan progress.                                       |
| `--quiet`, `-q`   | Suppress informational log output; warnings and errors are still shown. Ideal for CI/CD pipelines.   |

### Excluding paths

Two complementary mechanisms control which paths are scanned:

**`--exclude` (CLI flag, repeatable).** Best for ad-hoc exclusions during a single
invocation:

```sh
codesentinel . --exclude "third_party/**" --exclude "**/*.min.js"
```

**`.codesentinelignore` (file in the scan root).** Best for project-level
exclusions that should apply to every run:

```
# CodeSentinel ignore patterns — one glob per line, # for comments.
third_party/**
docs/**
**/*.generated.cs
```

Patterns from both sources are combined. When scanning a repository you do not
control, pass `--no-ignore-file`: its `.codesentinelignore` is written by the
same people whose code you are checking. Note that CodeSentinel also skips a
default set of directories (`.git`, `node_modules`, `bin`, `obj`, `dist`,
`build`, `vendor`, `__pycache__`, `target`, `.terraform`, and similar) without
requiring explicit configuration. These names are matched below the scan root
only, so a repository that itself lives in a folder called `build` is still
scanned.

### Suppressing a single finding

To silence a known false positive without excluding the whole file, add a
`codesentinel:ignore` comment on the same line. List rule IDs to limit it to
specific rules:

```python
api_key = "documented-example-value"   # codesentinel:ignore
token = load_fixture("token.txt")      # codesentinel:ignore CS005, CS900
```

The number of suppressed findings is printed at the end of the scan.
`--no-inline-ignore` reports them anyway. See
[ADR 0010](docs/adr/0010-inline-suppression-comments.md).

### Exit codes

CodeSentinel returns deterministic exit codes designed for CI/CD pipelines:

| Code | Meaning                                                                  |
| ---- | ------------------------------------------------------------------------ |
| `0`  | Scan completed without findings (or none at or above `--fail-on`).       |
| `1`  | Scan completed with findings at or above the threshold.                  |
| `2`  | Scan did not complete: invalid path, clone failure, cancellation (Ctrl+C), or an unexpected error. |

Code `1` is never used for errors, so a pipeline can tell a dirty repository
from a broken scan.

Credentials embedded in a remote URL (`https://<token>@github.com/...`) are
masked in logs and in the report header.

### Example: GitHub Actions

Upload the report as a build artifact and push SARIF findings into the
repository's Security tab:

```yaml
- name: Run CodeSentinel (SARIF)
  run: dotnet run --project src/CodeSentinel.Cli -- . --fail-on High -o codesentinel.sarif

- name: Upload SARIF to GitHub code scanning
  if: always()
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: codesentinel.sarif
```

`--fail-on High` blocks the merge only on High or Critical findings while still
surfacing Medium/Low/Info issues in the report — a common DevSecOps pattern that
keeps signal high without ignoring lower-severity warnings. Uploading SARIF
makes each finding visible inline on the affected file in the GitHub Security
tab, with the rule description shown next to the source line.

## Docker

CodeSentinel ships a `Dockerfile` that builds a self-contained Linux binary on
top of a chiseled (distroless) .NET runtime base — no shell, no package
manager, single non-root user.

```sh
# Build the image
docker build -t codesentinel .

# Scan a repository by bind-mounting it at /scan
docker run --rm -v "$(pwd):/scan" codesentinel /scan

# Write a SARIF report to the mounted volume
docker run --rm -v "$(pwd):/scan" codesentinel /scan -o /scan/report.sarif --fail-on High
```

The image runs as a non-root user. The mounted volume must allow that user to
read source files and (if `--output` is used) write into the chosen directory.

## Releasing

Pushing a tag such as `v0.2.0` runs `.github/workflows/release.yml`, which:

1. builds and tests the solution with that version;
2. packs the global tool and attaches the `.nupkg` to a GitHub Release with
   generated notes;
3. pushes the Docker image to `ghcr.io/<owner>/codesentinel` tagged `0.2.0`,
   `0.2` and `latest`;
4. publishes the package to nuget.org, but only when a `NUGET_API_KEY`
   repository secret is configured.

```sh
git tag v0.2.0
git push origin v0.2.0
```

Move the `[Unreleased]` entries in `CHANGELOG.md` under the new version before
tagging.

## Listing rules

To see which rules are bundled with the binary, run:

```sh
codesentinel list-rules
```

Output:

```
ID     SEVERITY  CATEGORY         TITLE
CS001  Critical  Secret           AWS Access Key ID
CS002  Critical  Secret           AWS Secret Access Key
CS003  Critical  Secret           Private Key
CS004  High      Secret           JSON Web Token
CS005  High      Secret           Hardcoded Credential
CS101  Medium    InsecurePattern  Weak Hash Algorithm
CS900  Medium    Secret           High-Entropy String
```

## Security score

The `ISecurityScorePolicy` weights each finding by severity and produces a
0–100 value with a corresponding letter grade.

| Severity   | Penalty |
| ---------- | ------- |
| Critical   | 25      |
| High       | 15      |
| Medium     | 8       |
| Low        | 3       |
| Info       | 1       |

| Grade | Range  |
| ----- | ------ |
| A     | 90–100 |
| B     | 75–89  |
| C     | 60–74  |
| D     | 40–59  |
| F     | 0–39   |

Repositories with no findings score `100 (A)`. The scoring policy is a
registered service, so projects with different priorities can swap in a
custom implementation.

## Sample output

JSON report (excerpt):

```json
{
  "scanner": "CodeSentinel",
  "version": "0.1.0",
  "scannedAt": "2026-05-08T02:42:22+00:00",
  "target": "/repo",
  "summary": {
    "filesScanned": 4,
    "findingCount": 16,
    "duration": "00:00:00.145",
    "score": { "value": 0, "grade": "F" }
  },
  "findings": [
    {
      "ruleId": "CS001",
      "title": "AWS Access Key ID",
      "severity": "Critical",
      "confidence": 0.9,
      "location": {
        "file": ".env",
        "line": 5,
        "column": 19,
        "snippet": "AWS_ACCESS_KEY_ID=[REDACTED]"
      }
    }
  ]
}
```

HTML reports are self-contained: embedded CSS, no external assets, safe to
email or host. Severity-coded badges and a circular score dial make findings
easy to triage at a glance.

## Architecture

CodeSentinel follows clean architecture with strict, inward-pointing dependencies:

```
Cli ──┬──→ Application ──→ Core
      │
      └──→ Infrastructure ──→ Application, Core
```

| Project                       | Responsibility                                                   |
| ----------------------------- | ---------------------------------------------------------------- |
| `CodeSentinel.Core`           | Domain model: findings, rule contracts, scan results, scoring.   |
| `CodeSentinel.Application`    | Use cases and ports (file source, rule provider, report writer). |
| `CodeSentinel.Infrastructure` | Adapters: file walker, built-in rules, JSON/HTML/SARIF writers, Git cloner. |
| `CodeSentinel.Cli`            | Command-line entry point and DI composition root.                |

**Why this structure:** the scanning core has zero external dependencies — no
I/O, no Git, no HTTP. Detection rules are `IDetectionRule` implementations,
file sources are `IFileSource` implementations, and report writers are
`IReportWriter` implementations. New formats and rules plug in without
touching the orchestrator.

Files are analysed in parallel, one worker per core, and findings are sorted
afterwards so results are identical from run to run. On a synthetic repository
of 5,000 source files (1.5 million lines) plus 30,000 files in `node_modules`,
a scan takes about 2.3 seconds on a 12-core machine, down from 7.3 seconds
before the work described in [ADR 0007](docs/adr/0007-parallel-scanning.md).

The reasoning behind these and other design choices is recorded as
[Architecture Decision Records](docs/adr/README.md).

## Build and test

```sh
dotnet build CodeSentinel.sln
dotnet test  CodeSentinel.sln
```

The repository ships two GitHub Actions workflows in `.github/workflows/`:

| Workflow      | What it does                                                                    |
| ------------- | ------------------------------------------------------------------------------- |
| `build.yml`   | Restores, builds, and runs the full test suite on Linux, Windows, and macOS.   |
| `security.yml`| Runs CodeSentinel against its own source and uploads SARIF to the Security tab. |

The security workflow uses a `.codesentinelignore` in the repo root that
excludes `samples/**` (deliberately-vulnerable fixtures) and `tests/**` (test
data that intentionally contains rule-matching patterns).

Test layout:

| Project                              | Coverage                                                |
| ------------------------------------ | ------------------------------------------------------- |
| `CodeSentinel.Core.Tests`            | Domain types and scoring.                               |
| `CodeSentinel.Application.Tests`     | Orchestrator, report service, DI wiring.                |
| `CodeSentinel.Infrastructure.Tests`  | File walker, individual rules, writers, integration.    |
| `CodeSentinel.Cli.Tests`             | End-to-end CLI invocations against real fixtures.       |

## Requirements

- .NET 8 SDK or newer
- Windows, Linux, or macOS

## Repository layout

```
src/         Production projects (Core, Application, Infrastructure, Cli).
tests/       Unit and integration test projects.
samples/     Deliberately-vulnerable fixtures used by tests and demos.
docs/adr/    Architecture Decision Records.
```

## Roadmap

- Phase 1 — Architecture and planning. **Done.**
- Phase 2 — Solution scaffolding, dependency wiring, smoke tests. **Done.**
- Phase 3 — Core detection engine: built-in rules, entropy heuristic, file walker. **Done.**
- Phase 4 — Reporting: JSON and HTML report writers, CLI integration. **Done.**
- Phase 5 — CLI surface refinements: `--fail-on` threshold, `--exclude` + `.codesentinelignore`,
  `list-rules` subcommand, `--verbose` / `--quiet` log levels. **Done.**
- Phase 6 — SARIF writer, Dockerfile, GitHub Actions CI/CD, remote Git scanning. **Done.**

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the version history. Releases follow
[Semantic Versioning](https://semver.org/).

## License

[MIT](LICENSE) — see the `LICENSE` file for the full text.
