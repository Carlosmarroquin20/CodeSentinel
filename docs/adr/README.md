# Architecture Decision Records

Each record captures one significant decision: the context that forced it, what
was decided, and the consequences we accepted. Records are immutable once
accepted. A later decision that changes course gets a new record that marks the
old one as superseded.

New records copy [`template.md`](template.md) and take the next free number.

| ADR | Title | Status |
| --- | ----- | ------ |
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | Accepted |
| [0002](0002-layered-architecture.md) | Layered architecture with inward dependencies | Accepted |
| [0003](0003-regex-rules-with-timeouts-and-redaction.md) | Regex detection rules with match timeouts and redaction | Accepted |
| [0004](0004-pluggable-report-writers.md) | Pluggable report writers: JSON, HTML and SARIF | Accepted |
| [0005](0005-strict-build-with-pinned-analysis-level.md) | Strict build with a pinned analysis level | Accepted |
| [0006](0006-treat-scanned-repositories-as-untrusted-input.md) | Treat scanned repositories as untrusted input | Accepted |
| [0007](0007-parallel-scanning.md) | Parallel scanning with deterministic results | Accepted |
| [0008](0008-consolidate-overlapping-secret-findings.md) | Consolidate overlapping secret findings | Accepted |
| [0009](0009-entropy-candidates-limited-to-secret-alphabets.md) | Entropy candidates limited to secret alphabets | Accepted |
| [0010](0010-inline-suppression-comments.md) | Inline suppression comments | Accepted |
| [0011](0011-exempt-integrity-digests-from-entropy.md) | Exempt integrity digests from the entropy rule | Accepted |
