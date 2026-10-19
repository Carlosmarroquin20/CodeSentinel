# 0004. Pluggable report writers: JSON, HTML and SARIF

- Status: Accepted (recorded retroactively)
- Date: 2026-10-19

## Context

Scan results have three audiences: tools that post-process them, people who
read them, and code-scanning platforms that annotate pull requests. Each wants a
different format, and more formats are likely.

## Decision

- Formats implement `IReportWriter` (a `Format` name plus `WriteAsync`) and are
  registered in DI. `ReportService` picks the writer by name; the CLI infers the
  name from the output file extension when `--format` is omitted.
- JSON is the default machine-readable format.
- HTML is a single self-contained file. All values taken from scanned files are
  HTML-encoded, and the page declares a Content-Security-Policy that forbids
  scripts and external requests as a second layer.
- SARIF 2.1.0 is emitted for GitHub code scanning. Every registered rule is
  listed in `tool.driver.rules`; Critical and High map to `error`, Medium to
  `warning`, Low to `note` and Info to `none`. Regions include `endColumn`
  when the rule knows where the match ends.
- Writers sort findings by severity, then path, then line, so output is stable
  across runs.

## Consequences

- Adding a format does not touch the scanner or the CLI beyond the extension
  mapping.
- The SARIF output works with `github/codeql-action/upload-sarif` without
  post-processing, which the `security` workflow relies on.
- The HTML report cannot run JavaScript, so interactive features such as
  client-side filtering would require relaxing the policy on purpose.
