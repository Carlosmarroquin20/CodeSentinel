# CodeSentinel

Security scanner for source code repositories. Detects exposed secrets, insecure
coding patterns, and misconfigurations, and assigns a security score to each
scanned repository.

CodeSentinel is designed for DevSecOps integration: deterministic output,
machine-readable reports, and exit codes that fit naturally into CI/CD pipelines.

## Status

Early development. The scaffolding is in place; detection rules and reporting
arrive in subsequent phases (see [Roadmap](#roadmap)).

## Architecture

CodeSentinel follows clean architecture with strict, inward-pointing dependencies:

```
Cli  ->  Application  ->  Core
Cli  ->  Infrastructure  ->  Application, Core
```

| Project                       | Responsibility                                                  |
| ----------------------------- | --------------------------------------------------------------- |
| `CodeSentinel.Core`           | Domain model: findings, rule contracts, scoring policy.         |
| `CodeSentinel.Application`    | Use cases and ports (file source, rules, reporting).            |
| `CodeSentinel.Infrastructure` | Adapters: file walkers, Git access, rule loaders, report writers. |
| `CodeSentinel.Cli`            | Command-line entry point. DI composition root.                  |

The scanning core depends on nothing external. Detection mechanisms (regex,
entropy, future AST-based analyzers) plug in as `IDetectionRule` implementations.
The CLI today and a REST API tomorrow are thin entry points over the same
application use cases.

## Requirements

- .NET 8 SDK or newer
- Windows, Linux, or macOS

## Build and test

```sh
dotnet build CodeSentinel.sln
dotnet test  CodeSentinel.sln
```

## Run

Scan a repository and print a summary to the console:

```sh
dotnet run --project src/CodeSentinel.Cli -- <repository-path>
```

Write a structured report to disk:

```sh
dotnet run --project src/CodeSentinel.Cli -- <repository-path> --output report.json
dotnet run --project src/CodeSentinel.Cli -- <repository-path> -f html -o report.html
```

### Options

| Flag                | Description                                                                                          |
| ------------------- | ---------------------------------------------------------------------------------------------------- |
| `--format`, `-f`    | Report format: `json` or `html`. If omitted, inferred from `--output` extension; otherwise `json`.   |
| `--output`, `-o`    | Path where the report will be written. If omitted, no file is created.                               |

### Exit codes

| Code | Meaning                                |
| ---- | -------------------------------------- |
| 0    | Scan completed without findings.       |
| 1    | Scan completed with findings.          |
| 2    | Scan failed (invalid path, I/O, etc.). |

## Roadmap

- Phase 1 — Architecture and planning. **Done.**
- Phase 2 — Solution scaffolding, dependency wiring, smoke tests. **Done.**
- Phase 3 — Core detection engine: built-in rules, entropy heuristic, file walker. **Done.**
- Phase 4 — Reporting: JSON and HTML report writers, CLI integration. **Done.**
- Phase 5 — CLI surface: severity thresholds, filters, rule listing, ignore-file support.
- Phase 6 — Optional: Docker image, CI/CD example, remote repository scanning,
  SARIF output.

## Repository layout

```
src/                 Production projects (Core, Application, Infrastructure, Cli).
tests/               Unit and integration test projects.
samples/             Fixtures used by tests and demos (later phases).
rules/               Default ruleset shipped with the binary (later phases).
docs/                Architecture and rule-authoring documentation (later phases).
build/               Dockerfile and CI definitions (later phases).
```

## License

To be determined.
