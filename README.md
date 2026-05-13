# CodeSentinel

Security scanner for source code repositories. Detects exposed secrets, insecure
coding patterns, and misconfigurations — then assigns a security score so the
result is easy to act on in code review and CI/CD.

Built from scratch on .NET 8 with a clean, extensible architecture: rules are
plug-in components, file sources can be swapped (local today, Git remote later),
and report writers compose freely (JSON and HTML today, SARIF later).

## Status

MVP complete. Scanning engine, scoring, JSON/HTML/SARIF reporting, CLI surface,
Docker image, GitHub Actions integration, and remote-repository support are all
in place. **177 tests passing** across Core, Application, Infrastructure, and CLI layers.

## What it detects

| Rule    | Category         | Severity   | Detects                                                          |
| ------- | ---------------- | ---------- | ---------------------------------------------------------------- |
| `CS001` | Secret           | Critical   | AWS access key IDs (`AKIA…`, `ASIA…`)                            |
| `CS002` | Secret           | Critical   | AWS secret access keys in assignment expressions                 |
| `CS003` | Secret           | Critical   | PEM private key headers (RSA, EC, OpenSSH, DSA, PGP)             |
| `CS004` | Secret           | High       | JSON Web Tokens                                                  |
| `CS005` | Secret           | High       | Hardcoded passwords, API keys, secrets, and tokens               |
| `CS101` | Insecure Pattern | Medium     | MD5 / SHA-1 usage (.NET, Python, Java)                           |
| `CS900` | Heuristic        | Medium     | High-entropy strings (Shannon entropy ≥ 4.5)                     |

Findings include severity, confidence, a redacted snippet, and the file path
and line number. Snippets in secret-category rules are redacted before they
reach the report — actual credentials never appear in output.

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

Patterns from both sources are combined. Note that CodeSentinel also skips a
default set of directories (`.git`, `node_modules`, `bin`, `obj`, `dist`,
`build`, `vendor`, `__pycache__`, `target`, `.terraform`, and similar) without
requiring explicit configuration.

### Exit codes

CodeSentinel returns deterministic exit codes designed for CI/CD pipelines:

| Code | Meaning                                |
| ---- | -------------------------------------- |
| `0`  | Scan completed without findings.       |
| `1`  | Scan completed with findings.          |
| `2`  | Scan failed (invalid path, I/O, etc.). |

### Example: GitHub Actions

Upload the report as a build artifact and push SARIF findings into the
repository's Security tab:

```yaml
- name: Run CodeSentinel (SARIF)
  run: dotnet run --project src/CodeSentinel.Cli -- . --fail-on High -o codesentinel.sarif

- name: Upload SARIF to GitHub code scanning
  if: always()
  uses: github/codeql-action/upload-sarif@v3
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
| `CodeSentinel.Infrastructure` | Adapters: file walker, built-in rules, JSON/HTML writers.        |
| `CodeSentinel.Cli`            | Command-line entry point and DI composition root.                |

**Why this structure:** the scanning core has zero external dependencies — no
I/O, no Git, no HTTP. Detection rules are `IDetectionRule` implementations,
file sources are `IFileSource` implementations, and report writers are
`IReportWriter` implementations. New formats and rules plug in without
touching the orchestrator.

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
```

## Roadmap

- Phase 1 — Architecture and planning. **Done.**
- Phase 2 — Solution scaffolding, dependency wiring, smoke tests. **Done.**
- Phase 3 — Core detection engine: built-in rules, entropy heuristic, file walker. **Done.**
- Phase 4 — Reporting: JSON and HTML report writers, CLI integration. **Done.**
- Phase 5 — CLI surface refinements: `--fail-on` threshold, `--exclude` + `.codesentinelignore`,
  `list-rules` subcommand, `--verbose` / `--quiet` log levels. **Done.**
- Phase 6 — SARIF writer, Dockerfile, GitHub Actions CI/CD, remote Git scanning. **Done.**

## License

[MIT](LICENSE) — see the `LICENSE` file for the full text.
