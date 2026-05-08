# CodeSentinel

Security scanner for source code repositories. Detects exposed secrets, insecure
coding patterns, and misconfigurations — then assigns a security score so the
result is easy to act on in code review and CI/CD.

Built from scratch on .NET 8 with a clean, extensible architecture: rules are
plug-in components, file sources can be swapped (local today, Git remote later),
and report writers compose freely (JSON and HTML today, SARIF later).

## Status

Early development. Scanning engine, scoring, and reporting are functional.
**85 tests passing** across Core, Application, Infrastructure, and CLI layers.

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

## Quick start

```sh
# Build
dotnet build CodeSentinel.sln

# Scan a repository (console output only)
dotnet run --project src/CodeSentinel.Cli -- /path/to/repo

# Generate an HTML report
dotnet run --project src/CodeSentinel.Cli -- /path/to/repo -o report.html

# Generate a JSON report (for CI/CD)
dotnet run --project src/CodeSentinel.Cli -- /path/to/repo -o report.json
```

Or scan the bundled fixture to see what a vulnerable repository looks like:

```sh
dotnet run --project src/CodeSentinel.Cli -- samples/vulnerable-repo -o report.html
```

## CLI reference

```
codesentinel <path> [--format <fmt>] [--output <file>]
```

| Flag             | Description                                                                                          |
| ---------------- | ---------------------------------------------------------------------------------------------------- |
| `<path>`         | Repository root to scan (required).                                                                  |
| `--format`, `-f` | Report format: `json` or `html`. If omitted, inferred from `--output` extension; otherwise `json`.   |
| `--output`, `-o` | Path where the report will be written. If omitted, no file is created.                               |

### Exit codes

CodeSentinel returns deterministic exit codes designed for CI/CD pipelines:

| Code | Meaning                                |
| ---- | -------------------------------------- |
| `0`  | Scan completed without findings.       |
| `1`  | Scan completed with findings.          |
| `2`  | Scan failed (invalid path, I/O, etc.). |

### Example: GitHub Actions

```yaml
- name: Run CodeSentinel
  run: dotnet run --project src/CodeSentinel.Cli -- . -o codesentinel.json

- name: Upload report
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: security-report
    path: codesentinel.json
```

A non-zero exit code on findings fails the job, so secrets pushed to a pull
request fail the check before review.

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
- Phase 5 — CLI surface refinements: severity thresholds, filters, rule listing,
  `.codesentinelignore` support.
- Phase 6 — Optional: Docker image, CI/CD example, remote repository scanning,
  SARIF output (GitHub code scanning integration).

## License

To be determined.
