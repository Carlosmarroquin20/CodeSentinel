# 0010. Inline suppression comments

- Status: Accepted
- Date: 2026-10-19

## Context

Every scanner produces false positives: test fixtures, documentation examples,
public sample keys. Until now the only way to silence one was to exclude the
whole file with `--exclude` or `.codesentinelignore`, which also hides any real
secret added to that file later. Other scanners solve this with a marker on the
offending line (`gitleaks:allow`, `pragma: allowlist secret`).

## Decision

- A finding is dropped when its line contains `codesentinel:ignore`, matched
  case-insensitively, typically inside a comment.
- The marker can list rule IDs (`codesentinel:ignore CS005, CS900`). Then only
  findings from those rules are dropped; others on the same line are kept.
- The marker only affects its own line.
- The number of suppressed findings is logged at the end of the scan.
- `--no-inline-ignore` (`ScanRequest.HonorInlineSuppressions = false`) reports
  findings regardless of markers, for the same reason `--no-ignore-file` exists:
  in a repository you do not control, markers are written by the people whose
  code you are checking (see ADR 0006).

## Consequences

- False positives can be silenced precisely and visibly in code review, without
  excluding whole files.
- Suppressed findings do not appear in reports at all. A reviewer who wants to
  audit them runs the scan with `--no-inline-ignore`.
- A secret on a line that already carries a bare `codesentinel:ignore` marker
  will be hidden. Listing rule IDs narrows that risk.
