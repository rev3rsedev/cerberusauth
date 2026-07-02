# Changelog

## v1.0.1 - 2026-07-02

- Build with Go 1.26.4 (`toolchain` directive in go.mod). The v1.0.0
  binaries were built with Go 1.25.0, which carries known standard
  library vulnerabilities fixed upstream, so that release was pulled
  minutes after publication and never distributed. No code changes.
- README: install options for release binaries and the ghcr.io image,
  rate-limiting notes brought up to date.

## v1.0.0 - 2026-07-02

First stable release.

Added:

- Go client SDK (`client/`): verify-then-parse, nonce echo, clock-skew
  self-correction, offline re-verification of cached verdicts, multi-key
  pinning. Standard library only.
- C# client SDK (`sdk/csharp/`): same protocol and semantics for
  netstandard2.1 and net8.0; tests include a Go-signed vector so the two
  implementations cannot drift apart.
- Embedded admin dashboard at `/`: apps, license issuing with one-time
  key display, ban/unban, HWID reset, key rotation, audit trail. Three
  static files, same-origin CSP, no build step. `CERBERUS_DASHBOARD=false`
  disables it.
- Key rotation with overlapping validity: `app_keys` table, one active
  key per app enforced by the database, retired keys stay on the pubkey
  endpoint. `POST /v1/admin/apps/{id}/rotate-key`,
  `GET /v1/admin/apps/{id}/keys`, `cerberusd rekey` for master-key
  replacement, runbook in docs/KEY-ROTATION.md.
- Append-only audit log: every admin mutation and login event, actor
  attributed, `GET /v1/admin/audit`.
- Per-IP rate limiting on the client endpoints
  (`CERBERUS_CLIENT_RATE_BURST`/`_REFILL`, burst 0 disables).
- Prometheus metrics on a separate listener (`CERBERUS_METRICS_ADDR`):
  request counters and latency per endpoint group, verdict breakdown,
  build info.
- Hourly cleanup of expired admin tokens.
- Release automation: tagged builds publish linux/windows/mac binaries
  (amd64 + arm64) and a distroless image on ghcr.io.
- CI: govulncheck, golangci-lint, Dependabot, dotnet test.

Upgrading from v0.1.0: migrations 0002 (audit_log) and 0003 (app_keys)
apply on startup with `CERBERUS_AUTO_MIGRATE=true` (the default), or run
`cerberusd migrate`. Admin API responses keep their v0.1 shapes; the
client pubkey endpoint additionally lists all keys. Existing clients and
pinned keys keep working unchanged.

## v0.1.0 - 2026-07-02

Initial public release: Ed25519-signed license verdicts (failures signed
too), redeem/validate with HWID binding, tiers and expiry, ban/unban,
admin API with argon2id logins and hashed-only storage of emails and
license keys, embedded migrator, docker compose quickstart.
