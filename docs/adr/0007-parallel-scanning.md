# 0007. Parallel scanning with deterministic results

- Status: Accepted
- Date: 2026-10-19

## Context

The scanner processed one file at a time: walk, open the file to look for null
bytes, open it again to read lines, run every rule, move on. On a synthetic
repository of 5,000 source files (1.5 million lines) plus 30,000 files inside
`node_modules`, a scan took 7.25 seconds (median of five runs, 12 logical
cores), with the CPU mostly idle.

## Decision

Changes were applied one at a time and measured on the same corpus, keeping
only those that helped. Each step produced byte-for-byte the same set of
findings as the baseline.

| Step | Median wall time |
| ---- | ---------------- |
| Baseline | 7.25 s |
| Prune ignored directories while walking instead of filtering afterwards | 6.82 s |
| Read each file once into a buffer used for both the binary check and line splitting | 4.82 s |
| Analyse files in parallel with `Parallel.ForEachAsync`, one worker per core | 3.35 s |
| Call the allocation-free `Regex.IsMatch` before `Regex.Matches` | 2.33 s |

The resulting design:

- `LocalFileSource` walks and reads sequentially and yields decoded files.
- `ScanOrchestrator` runs all rules for a file on a worker, with the degree of
  parallelism bounded by `Environment.ProcessorCount`.
- Findings are sorted by path, line, column and rule ID once the scan ends, so
  results do not depend on completion order.
- Rules must be stateless and thread-safe. All built-in rules are: they hold
  only immutable metadata and a compiled `Regex`, which is safe to share.

## Rejected alternatives

- Reading files in parallel through a bounded channel inside the file source.
  Measured at 3.61 s against 3.35 s for sequential reading: once rules ran in
  parallel, I/O was no longer the bottleneck, and the extra coordination cost
  more than it saved.
- Server garbage collection. Measured at 4.60 s against 3.39 s for the default
  workstation collector on the same build.

## Consequences

- Large repositories scan roughly three times faster on multi-core machines.
- A rule that keeps mutable state between calls would be a bug. The
  requirement is stated on the `IDetectionRule` interface.
- Log lines for individual files may interleave out of order at debug
  verbosity.
