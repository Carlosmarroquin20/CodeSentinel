# 0008. Consolidate overlapping secret findings

- Status: Accepted
- Date: 2026-10-19

## Context

Rules are independent by design (ADR 0003), so one secret often matches several
of them. A GitHub token assigned to a variable called `token` produced three
findings: `CS006` GitHub token (Critical), `CS005` hardcoded credential (High)
and `CS900` high-entropy string (Medium). The score penalised the same leak
three times, 52 instead of 75, and reviewers saw three rows for one problem.

Simply keeping one finding per line would hide real problems: a minified JSON
file can hold several unrelated secrets on a single line.

## Decision

- Rules report where a match ends as well as where it starts
  (`FileLocation.EndColumnNumber`).
- After sorting, the orchestrator drops a finding from a `Secret` category rule
  when, on the same line, another `Secret` finding with a strictly higher
  severity covers an overlapping column range.
- Findings with equal severity, findings without an end column, findings whose
  spans do not overlap, and findings from other categories (for example weak
  hash algorithms) are always kept.

## Consequences

- One leaked credential counts once, under its most specific rule. On
  `samples/vulnerable-repo` this removed 5 duplicate findings out of 24; each
  removed finding was a second report of a secret that remained in the output.
- When two rules of equal severity match the same value, both are still
  reported. Making that case smarter would need a notion of rule specificity,
  which the rule contract does not have today.
- Custom rules that do not set an end column are never consolidated, which
  errs on the side of reporting too much.
