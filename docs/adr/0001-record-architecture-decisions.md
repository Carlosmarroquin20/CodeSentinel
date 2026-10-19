# 0001. Record architecture decisions

- Status: Accepted
- Date: 2026-10-19

## Context

CodeSentinel has made several decisions whose reasons are not visible in the
code: why layers are split the way they are, why the analyzer level is pinned,
why the scanner refuses to follow symbolic links. Without a record, the next
change to those areas has to rediscover the reasoning or risks undoing it.

## Decision

We keep Architecture Decision Records in `docs/adr/`, one Markdown file per
decision, in the format described by Michael Nygard: context, decision,
consequences. Records are numbered sequentially and never rewritten after they
are accepted; a reversal is a new record that supersedes the old one.

Decisions made before this record existed (0002 to 0004) are written down
retroactively from the code and commit history.

## Consequences

- Reviewers can link to a record instead of re-arguing a settled question.
- Changing a recorded decision requires writing down why, which is a small,
  deliberate cost.
- Records can drift from the code if a change ignores them; the index in
  `docs/adr/README.md` is the place to check status.
