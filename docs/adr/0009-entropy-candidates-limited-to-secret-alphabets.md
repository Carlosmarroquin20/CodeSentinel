# 0009. Entropy candidates limited to secret alphabets

- Status: Accepted
- Date: 2026-10-19

## Context

`CS900` flags quoted strings of 20 or more characters whose Shannon entropy is at
least 4.5 bits per character. Candidates could contain any character except
quotes, whitespace and backslashes.

Scanning `serilog/serilog` produced 187 findings, all from `CS900` and all false
positives: 183 ReSharper `.DotSettings` keys
(`/Default/CodeEditing/Intellisense/.../@EntryValue`), MSBuild conditions, a
regular expression and an XML documentation reference. Long structured strings
use many distinct characters and clear the threshold easily. A scanner that
reports nearly two hundred false alarms on a well-known library teaches people
to ignore it.

## Decision

- Candidates must consist only of characters from the alphabets secrets are
  generated in: `A-Z a-z 0-9 + / = _ -` (base64, base64url and hex).
- Candidates must contain at least one digit and at least one letter.
- The 4.5-bit threshold stays. Hex strings top out at 4 bits per character, so
  hex values are not reported by `CS900`; commit SHAs, checksums and lockfile
  integrity hashes would otherwise dominate the output.

## Consequences

- `serilog/serilog` goes from 187 findings to 0. `samples/vulnerable-repo` is
  unchanged, and on the 1.5-million-line benchmark corpus 8 of 5,992 findings
  disappear: generated strings that happened to contain no digit.
- A real base64 secret with no digit is now missed. For a random 20-character
  base64 string that happens about 1.5% of the time ((52/64)^20); longer
  secrets are even less likely to lack a digit.
- Hex-encoded secrets need a dedicated pattern rule. None exists yet.
- Secrets embedded in structured strings (a key inside a URL query or an XML
  attribute together with other text) are left to the pattern rules.
