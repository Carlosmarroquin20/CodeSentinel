# Security policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

Fixes are released from `main`. Older versions do not receive backports.

## Reporting a vulnerability

Please do not open a public issue for security problems.

Report them privately through GitHub: open the repository's **Security** tab and
choose **Report a vulnerability**. Include:

- the CodeSentinel version (`codesentinel --version`) and how it was installed
  (global tool, Docker image or source build);
- the command line you ran and, if possible, a minimal repository or file that
  reproduces the problem;
- what you expected and what happened instead.

You can expect an acknowledgement within seven days. Once the issue is
confirmed, a fix is prepared on a private branch and published together with a
GitHub security advisory that credits the reporter, unless you prefer to stay
anonymous.

## Scope

CodeSentinel reads repositories that may be controlled by an attacker, so the
following are treated as vulnerabilities:

- a scanned repository causing CodeSentinel to read, write or report files
  outside the scan root;
- a raw secret value appearing in a report, log line or SARIF file;
- script execution or external requests from a generated HTML report;
- input that makes a scan hang indefinitely or exhaust memory.

Detection gaps, where a secret is not found, are bugs rather than
vulnerabilities and can be reported as regular issues, as long as the report
does not include a real credential.
