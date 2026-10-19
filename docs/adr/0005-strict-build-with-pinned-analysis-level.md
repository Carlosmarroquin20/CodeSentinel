# 0005. Strict build with a pinned analysis level

- Status: Accepted
- Date: 2026-10-19

## Context

The build treats every warning as an error and enforces code style
(`TreatWarningsAsErrors`, `EnforceCodeStyleInBuild`). That keeps the codebase
clean, but it also makes analyzer behaviour part of the build contract.

`AnalysisLevel` was set to `latest-recommended`. Hosted CI runners ship newer
.NET SDKs than developer machines, and each SDK brings new analyzer rules. When
the runners moved to an SDK that introduced CA1873, every build and every
self-scan failed without any change to the code. The Docker image failed for a
related reason: its build stage used the 8.0 SDK image, whose older analyzers
flag code the newer SDKs accept, and it did not copy `.editorconfig`.

## Decision

- `AnalysisLevel` is pinned to an explicit version (`9.0-recommended`) in
  `Directory.Build.props`. Raising it is a deliberate change made together with
  any code fixes it requires.
- Rules we choose not to follow are disabled in `.editorconfig` with a comment
  explaining why (CA1848 and CA1873: logging-performance rules whose benefit is
  negligible for a CLI).
- The Docker build stage uses the same SDK major version as the CI runners and
  copies `.editorconfig`, so the image builds under the same rules as CI.
- CI builds the Docker image and packs the global tool on every push, so any
  divergence shows up immediately.

## Consequences

- An SDK update on the runners no longer breaks the build by itself.
- New analyzer rules are not picked up automatically; someone has to raise the
  level on purpose.
- The project still targets `net8.0` while building with newer SDKs. Moving the
  target framework to .NET 10 (LTS) is tracked separately and should also add a
  `global.json` that pins the SDK.

## Update 2026-10-19

The projects now target `net10.0`, `global.json` pins the 10.0 SDK, and
`AnalysisLevel` was raised to `10.0-recommended`. The new level introduced no
diagnostics in this codebase.
