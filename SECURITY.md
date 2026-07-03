# Security Policy

CerberusAuth is a security product; reports that break it are the most
valuable contributions it can receive.

## Reporting a vulnerability

**Do not open a public issue for a vulnerability.**

Use [GitHub private vulnerability reporting](../../security/advisories/new)
(the "Report a vulnerability" button under the Security tab). That opens a
private thread with the maintainers and, once a fix ships, converts into a
published advisory with credit to you.

Include what you would want to receive: affected endpoint or package, a
reproduction (curl transcript, failing test, or PoC), and your assessment of
impact. A working exploit beats a speculative one, but a plausible
description of a real weakness is welcome too.

## What to expect

This is a small one-person project, not a security team with a pager.
Commitments:

- **Acknowledgment within 7 days.**
- **Assessment and a fix plan (or a reasoned dispute) within 30 days.**
- Coordinated disclosure: we agree on a publication date together;
  reasonable default is when the fixed release is out.
- Credit in the advisory and release notes unless you prefer otherwise.

## Scope

**In scope**, the server and protocol:

- `cerberusd` and everything under `internal/` and `cmd/`: signature
  forgery or bypass, authentication/authorization breaks in the admin API,
  license-state manipulation (validating a banned/expired/foreign license),
  replay beyond the documented client-side nonce model, SQL injection,
  key-material leaks (master key, derived keys, private signing keys),
  timing side channels that reveal account or license existence.
- The reference client's verification sequence
  (`examples/client-verify`): anything that makes verify-then-parse
  accept a forged or tampered payload.

**Out of scope**, per the documented non-goals (see the threat model in
[README.md](README.md) and [ARCHITECTURE.md](ARCHITECTURE.md)):

- Patched or modified client binaries skipping their own license checks.
  No licensing server can prevent that.
- Denial of service by volume. Admin login and the client endpoints are
  rate-limited per IP; a determined flood is documented as "front with a
  reverse proxy".
- Deployments running the published dev master key with
  `CERBERUS_DEV_MODE=true`. The tripwire exists so this cannot happen
  silently; a sandbox that opts in is out of scope.
- Vulnerabilities purely in dependencies: report upstream. If CerberusAuth
  uses the dependency in an exploitable way, that usage is in scope.

## Supported versions

Only the latest release gets fixes. There are no backports.
