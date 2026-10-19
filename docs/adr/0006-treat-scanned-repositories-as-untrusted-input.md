# 0006. Treat scanned repositories as untrusted input

- Status: Accepted
- Date: 2026-10-19

## Context

CodeSentinel scans local paths and clones arbitrary Git remotes. The content of
those repositories is controlled by whoever wrote them, and the reports are
often published: uploaded as SARIF to GitHub, attached to CI runs, or shared as
HTML. A review of the scanner found several ways the input could reach places
it should not:

- The file walker followed symbolic links, so a committed link to
  `~/.aws/credentials` or `/etc` would be read and could appear in snippets.
- A remote URL with embedded credentials (`https://<token>@host/repo.git`) was
  written verbatim to the console log and to the report header.
- Ignored directory names (`build`, `packages`, `bin`, ...) were matched against
  the absolute path, so a repository located under such a folder was silently
  scanned as empty and scored 100.
- Any unexpected exception, including Ctrl+C, ended with exit code 1, which CI
  pipelines read as "findings above threshold".

## Decision

- The walker never follows symbolic links or junctions
  (`AttributesToSkip = ReparsePoint`) and skips directories it cannot open.
- Ignored directory names are matched only below the scan root, while
  descending, so ignored trees are never entered.
- `UrlRedaction.RedactUserInfo` masks the user-info part of remote URLs
  everywhere the URL is echoed back. The conventional `git` user is kept.
- Exit codes are a contract: `0` clean, `1` findings at or above the threshold,
  `2` anything else, including cancellation and unexpected errors.
- The HTML report carries a restrictive Content-Security-Policy in addition to
  encoding every value (see ADR 0004).
- A remote clone is aborted through libgit2's transfer-progress callback when
  the scan is cancelled, and its temporary directory is always removed.

## Consequences

- Secrets stored behind a symlink inside the repository are not scanned. That
  is intentional: the link target is outside the repository's control.
- A repository's own `.codesentinelignore` is still honoured for remote scans.
  An attacker who controls the repository can therefore hide files from the
  scan. Scanning third-party code adversarially would need an option to ignore
  that file; it is not implemented yet.
- CI can distinguish "the code has problems" from "the scanner failed" and
  react differently to each.

## Update 2026-10-19

The `--no-ignore-file` option now skips the repository's `.codesentinelignore`,
which closes the gap described above for adversarial scans. The file is still
honoured by default because for a project scanning itself it is trusted
configuration.
