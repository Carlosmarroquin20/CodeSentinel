# 0012. MCP server over stdio for AI agents

- Status: Accepted
- Date: 2026-11-04

## Context

Coding agents such as Claude Code and Cursor write and change code on their own,
including configuration files where credentials tend to end up. They can already
run `codesentinel` through a shell, but then they have to parse console logs or
a report file, and nothing tells them what the tool does or how to fix what it
finds.

The Model Context Protocol (MCP) is the common way for these clients to discover
and call external tools. A server describes each tool with a name, a description
written for the model, a JSON schema for its arguments and annotations such as
"read-only". Clients support two transports: stdio, where the client starts the
server as a child process and exchanges JSON-RPC messages over stdin and stdout,
and streamable HTTP, where the server listens on a port.

An agent is not a trusted caller. The arguments it sends are written by a model
that may be acting on text it read in the repository, so a README or a comment
can try to steer it towards other paths on the machine (ADR 0006 already treats
scanned content as untrusted).

## Decision

- A new executable, `src/CodeSentinel.Mcp` (`codesentinel-mcp`), built on the
  official C# SDK (`ModelContextProtocol`). It composes the same Application and
  Infrastructure services as the CLI and has no scanning logic of its own. The
  only code that both entry points needed, reading `.codesentinelignore`, moved
  behind the `IIgnoreFileReader` port.
- It is a separate project rather than a CLI subcommand, so the CLI does not
  take on the SDK and `Microsoft.Extensions.Hosting`, and so the stdio rules
  below cannot affect the CLI's console output.
- Three tools, all annotated read-only, non-destructive, idempotent and closed
  world: `scan_path`, `list_rules` and `explain_rule`. Results are structured
  content with an output schema; severities and categories are names, not
  numbers.
- Only the stdio transport. The server is started by the client, runs as the
  user, and talks only to its parent process. There is no port to bind, so no
  authentication, TLS or origin checks to get right, and no way for another
  user or host on the network to reach it.

Security decisions:

- **Allowed roots.** `scan_path` only reads directories inside roots chosen by
  whoever launches the server: `--allowed-root` (repeatable), else
  `CODESENTINEL_MCP_ALLOWED_ROOTS`, else the working directory. Roots must be
  absolute, existing directories; invalid configuration stops the server with
  exit code 1. The agent cannot change them.
- **Path validation.** The requested path is resolved against the first root,
  normalized with `GetFullPath`, and accepted only if it equals a root or starts
  with a root followed by a separator, so `/srv/repo-backup` does not pass for
  `/srv/repo`. URLs, UNC paths and Win32 device paths (`\\?\`, `\\.\`) are
  rejected. Comparison ignores case on Windows and macOS and respects it
  elsewhere.
- **No links on the way in.** A path is rejected if the target or any directory
  between it and its root is a symbolic link or junction. The file walker
  already refuses to follow links below the scan root (ADR 0006); this covers
  the scan root itself.
- **Local paths only.** Git URLs are refused. Cloning would let an agent make
  the machine fetch arbitrary remotes.
- **Read-only.** The server writes no files: no reports, no fixes. Rejections
  are tool errors that say what was wrong and list the allowed roots, so the
  agent can correct the call.
- **Redaction.** Findings carry the snippet exactly as the rule produced it, so
  secret values are already replaced with `[REDACTED]` (ADR 0003). The agent
  receives the same snippets a JSON or SARIF report would contain, never more.
- **stdout belongs to the protocol.** All logging goes to stderr, including
  startup errors. The host is created with `CreateEmptyApplicationBuilder`,
  which also means it does not read `appsettings.json` or environment-based
  configuration from the working directory, usually the repository the agent is
  working on.
- **Bounded output.** `scan_path` returns at most 500 findings (50 by default),
  most severe first, and reports whether the list was cut. The score and the
  per-severity counts always cover every finding.
- **Suppressions stay visible to the caller.** `.codesentinelignore` and
  `codesentinel:ignore` are honoured by default, as in the CLI, and the tool
  description tells the agent to turn them off for code it does not trust
  (ADR 0006, ADR 0010).

## Consequences

- Agents can scan the code they are editing, read a score and a list of
  findings without parsing logs, and ask how to fix each one.
- The path check happens before the scan starts. Someone who can already write
  to the disk could replace a checked directory with a link in between; we
  accept that race, since such a user has easier ways to read the files.
- The server does not limit what the agent can do by other means. An agent
  with shell access can read any file the user can. The allowed roots limit
  what this server will read on the agent's behalf, not the agent.
- Error messages reveal the allowed roots to the agent. They are chosen by the
  same user who runs the agent, and knowing them is what lets the agent retry
  with a valid path.
- `explain_rule` reads from a guidance catalog kept in the MCP project. A test
  fails when the catalog and the registered rules differ, so a new rule needs an
  explanation before it ships.
- A remote or shared deployment would need the HTTP transport with
  authentication. That is a separate decision if it is ever needed.
