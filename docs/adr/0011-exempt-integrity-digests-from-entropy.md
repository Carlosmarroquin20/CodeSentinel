# 0011. Exempt integrity digests from the entropy rule

- Status: Accepted
- Date: 2026-10-19

## Context

[ADR 0009](0009-entropy-candidates-limited-to-secret-alphabets.md) expected
lockfile integrity hashes to stay below the `CS900` threshold because hex
digests carry at most 4 bits per character. npm does not use hex: every package
in `package-lock.json` has an `"integrity"` field in Subresource Integrity
format, an algorithm prefix followed by a base64 digest
(`sha512-UqC2k6S6...==`). Those values are quoted, use only base64 characters,
contain digits and letters, and clear 4.5 bits per character.

Scanning a small Node application with three lockfiles produced 2,372 findings,
all from `CS900` and all integrity values, for a score of 0 (F). Excluding
`**/package-lock.json` brought it to 0 findings. HTML pages that load scripts
from a CDN use the same format in `integrity="sha384-..."` attributes.

Two fixes were considered:

- Skip well-known lockfiles by default, like `node_modules`. Simple, but a
  token pasted into a lockfile (for example in a `resolved` registry URL) would
  no longer be scanned by any rule.
- Recognise integrity digests inside `CS900`. The other rules keep scanning
  lockfiles, and HTML attributes are covered too.

## Decision

- `CS900` ignores a candidate that is exactly an integrity digest: `sha1-`,
  `sha256-`, `sha384-` or `sha512-` followed by a base64 body of the length
  that algorithm produces (27, 43, 64 or 86 characters plus padding).
- Lockfiles are scanned like any other file.

## Consequences

- The Node application above goes from 2,372 findings to 0 without any
  exclusion. `samples/vulnerable-repo` is unchanged.
- A secret only escapes `CS900` if it is written with a digest prefix and has
  exactly the digest length. The pattern rules still apply to it.
- yarn and pnpm lockfiles write integrity values without quotes, so `CS900`
  never considered them candidates; they are unaffected.
