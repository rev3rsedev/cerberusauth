# CerberusAuth Architecture

> Status: v0.1 (MVP). This document describes what exists today and records the
> reasoning behind the load-bearing decisions. When behavior and this document
> disagree, the document is wrong — fix it.

## Overview

CerberusAuth is a self-hostable authentication and software-licensing server.
A vendor runs one instance; each product they ship is an **Application**
(tenant). The server issues license keys, and client software calls back to
redeem and validate them. The core promise: **validation responses are
Ed25519-signed, so a client can trust an answer without trusting the network
path it arrived over.**

```
┌────────────┐   HTTPS (reverse proxy, out of scope)   ┌─────────────────┐
│ Client app │ ──── POST /v1/client/validate ────────▶ │    cerberusd     │
│ (ships w/  │ ◀─── signed payload + signature ─────── │  (single binary) │
│  pinned    │                                          │                 │
│  pubkey)   │                                          └───────┬─────────┘
└────────────┘                                                  │ pgx
                    ┌───────────────┐                   ┌───────▼─────────┐
                    │ Admin (curl / │ ── Bearer token ─▶│   PostgreSQL     │
                    │ future UI)    │                   └─────────────────┘
                    └───────────────┘
```

One Go binary (`cerberusd`), one PostgreSQL database, configuration via
environment variables. No other moving parts.

## Repository layout

```
cmd/cerberusd/          entrypoint: serve | migrate | create-admin | genkey
internal/
  config/               env-var parsing (12-factor), defaults, validation
  signing/              Ed25519 keypairs, sign/verify, private-key encryption at rest
  license/              key generation, formatting, canonicalization, hashing
  auth/                 argon2id password hashing, admin tokens, email HMAC
  service/              business logic: redeem, validate, admin operations
  store/                domain types + Store interface (no SQL here)
    storetest/          in-memory Store fake shared by unit tests
    postgres/           pgx implementation + embedded migrations/*.sql
  server/               HTTP handlers, routing, middleware, JSON envelopes
```

Dependency direction: `server → service → store ← store/postgres`. The
service layer never imports pgx; handlers never touch SQL. Tests for the
service and HTTP layers run against `storetest.FakeStore` — `make test`
needs no database.

## Decision log

### pgx (direct) instead of sqlc
The MVP has roughly fifteen queries. sqlc would add a codegen step every
contributor must install and keep in sync for marginal benefit at this size.
Hand-written pgx queries live in one file (`internal/store/postgres`), typed
against the `store.Store` interface, so the blast radius of a bad query is
contained and the swap to sqlc later is mechanical if the query count grows.

### stdlib `net/http` instead of chi
Go 1.22+ pattern routing (`POST /v1/client/validate`, `{id}` path values)
covers every route we have. Middleware is three small functions (recover,
logging, admin auth). chi earns its keep on bigger route trees; here it
would be a dependency that saves nothing.

### A ~70-line embedded migrator instead of golang-migrate
Migrations are `.sql` files embedded in the binary and applied in filename
order, tracked in a `schema_migrations` table, each inside a transaction,
guarded by a Postgres advisory lock so two replicas starting at once don't
race. This keeps the single-binary promise: `cerberusd migrate` (or
auto-migrate on boot) works anywhere the binary runs, no extra tool.

### Per-application signing keys, encrypted at rest
Every Application gets its own Ed25519 keypair at creation. Private keys are
stored AES-256-GCM-encrypted under a key derived from the 32-byte master key
supplied via `CERBERUS_MASTER_KEY`. The master key is never used directly:
HKDF-SHA256 expands it into independent subkeys per purpose — the encryption
key (info `cerberus/enc-v1`) and the email pepper (info `cerberus/email-v1`)
— so one primitive's key can never double as another's. Consequence: a
database dump alone is not enough to forge license responses — the attacker
also needs the master key from the environment. Honest limit: an attacker who can read the server's environment
or memory owns the signing keys. That is true of every design that signs
online; we just say it out loud.

Key rotation is deliberately out of scope for v0.1 (TODO: rotation with
overlapping validity, `key_id` already exists in the envelope to support it).

### Sign raw bytes, transport them base64-encoded
The signed unit is the exact JSON byte sequence the server produced. The
response envelope is:

```json
{
  "alg": "ed25519",
  "key_id": "1f2a9c3b8d4e5f60",
  "payload": "<base64(payload JSON bytes)>",
  "signature": "<base64(ed25519 signature over those bytes)>"
}
```

Clients MUST verify the signature over the decoded payload bytes *before*
parsing them. Because the signed bytes are transported verbatim, there is no
JSON canonicalization scheme to implement and no re-serialization ambiguity
to exploit. The envelope intentionally contains **no plaintext copy** of the
payload — a client that "forgets" to verify has nothing convenient to read.

### The signed payload

```json
{
  "v": 1,
  "valid": true,
  "reason": "",                  // set when valid=false, see below
  "app_id": "…",
  "license_id": "…",             // present when a license was found
  "tier": "pro",
  "expires_at": 1789200000,      // unix seconds; absent = perpetual
  "hwid": "…",                   // echoed from the request
  "nonce": "…",                  // echoed from the request
  "client_ts": 1751457600,       // echoed from the request
  "server_ts": 1751457601
}
```

Failure reasons: `invalid_key`, `not_redeemed`, `banned`, `expired`,
`hwid_mismatch`, `stale_timestamp`.

**Failures are signed too.** A network attacker must not be able to forge a
"banned" or "expired" verdict any more than a "valid" one. Clients should
fail closed when the signature does not verify, and treat unsigned transport
errors as "retry later", not as a verdict.

### Replay protection — and where it lives
Every client request carries a random `nonce` and a unix `timestamp`. The
server echoes both into the signed payload and rejects timestamps outside a
configurable skew window (`CERBERUS_CLOCK_SKEW`, default 5m) with a signed
`stale_timestamp` verdict.

The client-side check is the one that matters: **a client must verify that
the echoed nonce equals the nonce it just generated.** That makes every
response single-use — a captured "valid" response cannot be replayed to the
client later, because the nonce won't match.

There is deliberately **no server-side nonce store**. Replaying an old
*request* to the server merely produces a fresh signed response with the
current `server_ts` — the attacker gains nothing they couldn't get by
sending a new request. Skipping the nonce table keeps validation a single
indexed read.

### What is hashed, and how
| Data | Storage | Why |
|---|---|---|
| License keys | SHA-256 of canonical form | DB dump doesn't leak usable keys. High entropy (125 bits) → plain hash is fine, no salt needed. Plaintext shown exactly once, at issuance. |
| Admin passwords | argon2id (19 MiB, t=2, p=1 — OWASP baseline), PHC string | Standard password storage. |
| Admin API tokens | SHA-256 | High entropy (256 bits), lookup by hash. |
| Admin emails | HMAC-SHA-256, peppered with an HKDF-derived subkey of the master key (info `cerberus/email-v1`) | Emails are low-entropy; a plain hash would be enumerable offline from a dump. HMAC with a peppered key isn't. The pepper is derived, not the master key itself, so the AES key and the HMAC key stay independent. Trade-off: emails cannot be displayed or recovered, only matched at login. Accepted for v0.1. |
| HWIDs | SHA-256 | Opaque device identifiers; equality is all we need. |

License keys are 25 characters of Crockford base32 (alphabet without
I/L/O/U), grouped `XXXXX-XXXXX-XXXXX-XXXXX-XXXXX` — 125 bits from
`crypto/rand`. Canonicalization (uppercase, strip separators) happens before
hashing, so user-mangled input still matches.

### License lifecycle

```
issued ──(redeem: bind HWID, start clock)──▶ active ──(ban)──▶ banned
   │                                            ▲                 │
   └────────────(ban)──▶ banned ──(unban)───────┴─────(unban)─────┘
                                  (returns to active if it was redeemed,
                                   else to issued)
```

- **Expiry**: a license may carry `duration_seconds` (relative — the clock
  starts at redemption: `expires_at = redeemed_at + duration`) or a fixed
  `expires_at` set at issuance (absolute). If both are somehow set, the fixed
  date wins. Neither = perpetual.
- **HWID binding**: bound on first redeem/validate. Subsequent validations
  must present the same HWID. `reset-hwid` unbinds; the next validation
  binds the new device. Binding uses a conditional
  `UPDATE … WHERE hwid_hash IS NULL` so two devices racing for first bind
  cannot both win.
- **Redeem is idempotent** for the same HWID (a client that crashed after
  redeeming can safely retry); a different HWID gets `hwid_mismatch`.

### Admin authentication
`POST /v1/admin/login` with email + password returns a bearer token
(`cba_` + 256 bits, stored hashed, TTL `CERBERUS_ADMIN_TOKEN_TTL`, default
24h). Login does a dummy argon2 verification when the email is unknown so
the response time doesn't reveal account existence. There is no login rate
limiting yet (TODO v0.2) — put the admin API behind your reverse proxy's
limiter until then.

Bootstrap: `cerberusd create-admin -email … -password …`, or set
`CERBERUS_BOOTSTRAP_ADMIN_EMAIL/_PASSWORD` and the server creates that admin
on boot if it doesn't exist (idempotent, compose-friendly).

## HTTP surface (v0.1)

Client (unauthenticated — the license key is the credential):
```
POST /v1/client/redeem                    {app_id, license_key, hwid, nonce, timestamp}
POST /v1/client/validate                  {app_id, license_key, hwid, nonce, timestamp}
GET  /v1/client/apps/{app_id}/pubkey      convenience; clients should PIN the key at build time
GET  /healthz
```

Admin (Bearer token, except login):
```
POST /v1/admin/login
POST /v1/admin/apps                       create app (returns public key)
GET  /v1/admin/apps
GET  /v1/admin/apps/{id}
POST /v1/admin/apps/{id}/licenses         batch-issue; plaintext keys returned ONCE
GET  /v1/admin/apps/{id}/licenses         paginated list (key hints only)
GET  /v1/admin/licenses/{id}
POST /v1/admin/licenses/{id}/ban          {reason}
POST /v1/admin/licenses/{id}/unban
POST /v1/admin/licenses/{id}/reset-hwid
```

Error contract: client-endpoint outcomes that concern the *license* are
always HTTP 200 with a signed payload (so verdicts can't be spoofed).
Unsigned HTTP errors (400 malformed request, 404 unknown app, 500) concern
the *request*, and clients must not interpret them as license verdicts.

## Threat model (short form — README has the user-facing version)

Protects against: forged or tampered validation responses (MITM, hostile
proxies, DNS games), replayed "valid" responses, license-key theft from a
database dump, password-database cracking, offline email enumeration from a
dump.

Does **not** protect against: a patched client binary (nothing server-side
can; anyone promising otherwise is selling obfuscation), a compromised
server or leaked master key, key sharing before first HWID bind, denial of
service (no rate limiting in v0.1 — front with a proxy).

TLS is still required in deployment: signatures give integrity and
authenticity, not confidentiality — without TLS, license keys and HWIDs
transit readable.

## Extension points (deliberately stubbed)

- `TODO(v0.2)`: dashboard UI — consumes the same admin API; no server changes anticipated.
- `TODO(v0.2)`: client SDKs (Go/Rust/C#) — verify-then-parse helper + nonce bookkeeping.
- `TODO(v0.2)`: rate limiting middleware (hook exists in `internal/server/middleware.go`).
- `TODO(v0.2)`: audit log table; key rotation with overlapping `key_id`s.
- `TODO(v0.3)`: end-user accounts (KeyAuth-style user/pass per app), resellers, webhooks.
