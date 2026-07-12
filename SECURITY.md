# Security Policy

## Reporting a vulnerability

**Do not open a public issue for security vulnerabilities.**

Report them privately through GitHub's private vulnerability reporting:
**Security tab → Report a vulnerability** on this repository. Include:

- a description of the issue and its impact,
- steps to reproduce (a minimal repository or file that triggers it, if possible),
- the ovecc version (`ovecc --version`) and platform.

You will get an acknowledgement within 72 hours and a status update at least
weekly until the issue is resolved. Fixes ship in the next release; credit is
given in the changelog unless you prefer otherwise.

## Scope

ovecc runs fully offline against local repositories, so the attack surface is
deliberately small. Reports are especially welcome for:

- parser or indexer crashes/hangs on adversarial source files (untrusted repos
  are a normal input),
- path traversal or writes outside `.ovecc/` triggered by repository content,
- code execution through crafted repository content (config files, manifests,
  source),
- flaws in `ovecc audit`'s advisory matching that hide known vulnerabilities.

Findings *about your own code* that ovecc reports (or misses) are product
feedback, not vulnerabilities; please open a regular issue for those.

## Supported versions

Only the latest release is supported with security fixes.
