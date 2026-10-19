# 0002. Layered architecture with inward dependencies

- Status: Accepted (recorded retroactively)
- Date: 2026-10-19

## Context

A secret scanner has a small, stable core (what a finding is, how a score is
computed) surrounded by parts that change often: new rules, new report formats,
new ways to obtain source code (local paths, Git remotes). Mixing the two makes
every new rule or format a change to the scanning loop, and makes the core hard
to test without touching the file system.

## Decision

The solution is split into four projects with dependencies that only point
inward:

| Project | Owns | Depends on |
| ------- | ---- | ---------- |
| `CodeSentinel.Core` | Findings, severities, rule contract (`IDetectionRule`), scan request and result, score model | nothing |
| `CodeSentinel.Application` | Use cases and ports: orchestrator, report service, `IFileSource`, `IRuleProvider`, `IReportWriter`, `IRepositoryCloner`, scoring policy | Core |
| `CodeSentinel.Infrastructure` | Adapters: file walker, built-in rules, JSON/HTML/SARIF writers, LibGit2Sharp cloner | Application, Core |
| `CodeSentinel.Cli` | Argument parsing, exit codes, dependency injection composition root | Application, Infrastructure |

Implementations in Infrastructure are `internal` and registered through
`AddCodeSentinelInfrastructure()`; callers only see the ports.

## Consequences

- A new rule or report format is one class plus one DI registration; the
  orchestrator does not change.
- Core and Application have no I/O dependencies, so the orchestrator is tested
  with in-memory rules.
- Helpers that more than one outer layer needs, such as `UrlRedaction`, live
  in Application so that both Infrastructure and Cli can use them without
  depending on each other.
- Four projects is more ceremony than a single assembly would need at this
  size. We accept that in exchange for enforced boundaries.
