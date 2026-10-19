# 0003. Regex detection rules with match timeouts and redaction

- Status: Accepted (recorded retroactively)
- Date: 2026-10-19

## Context

Most secrets have a recognisable shape: a fixed prefix (`AKIA`, `ghp_`,
`xoxb-`, `sk_live_`) followed by a known alphabet and length. Some do not, and
can only be spotted by context (`password = "..."`) or by how random they look.

Two risks come with scanning arbitrary repositories:

1. A regular expression with poor backtracking behaviour can hang on a crafted
   or simply unusual line.
2. The report itself can become a leak if it echoes the secret it found.

## Decision

- Pattern rules derive from `RegexDetectionRule` and use compiled,
  culture-invariant expressions with a one-second match timeout.
- Context rules (`CS005`) capture the value in group 1. Shape-less secrets are
  covered by a Shannon-entropy heuristic (`CS900`) with a lower confidence
  (0.6, against 0.9 for pattern rules).
- Every rule in the `Secret` category replaces the matched value with
  `[REDACTED]` before the snippet leaves the rule. When a capture group exists
  only the group is redacted, so the key name stays visible for context.
- A rule that throws on a file, including a `RegexMatchTimeoutException`, is
  logged and skipped; the rest of the scan continues.

## Consequences

- Reports, logs and SARIF uploads never contain raw secret values.
- A pathological line costs at most one second per rule instead of hanging the
  scan.
- Regex rules miss secrets that do not follow a known shape. The entropy rule
  narrows that gap at the price of more false positives, which is why its
  confidence is lower.
- Several rules often match the same secret. That is handled after the scan
  rather than by making rules aware of each other (see ADR 0008).
