# CerberusAuth

**The open, trustworthy one.**

A self-hostable authentication and software-licensing platform — a modern,
genuinely open alternative to KeyAuth. Apache-2.0, no proprietary tiers, no
gated features, no phone-home. Self-hosting is not a fallback mode; it is the
product.

- **Signed verdicts.** Every license validation response is Ed25519-signed by
  a per-application key. Your client verifies the signature with a pinned
  public key, so a "valid" (or "banned") answer can be trusted even on a
  hostile network. Failures are signed too.
- **Replay-proof.** Requests carry a client nonce and timestamp; both are
  echoed inside the signed payload. A captured response can't be replayed —
  the nonce won't match.
- **Hashed at rest.** License keys, admin tokens, and HWIDs are stored as
  hashes. Admin emails are HMAC-peppered. Admin passwords are argon2id.
  Per-app signing keys are AES-256-GCM-encrypted under a master key that
  lives only in your environment.
- **Boring to operate.** One Go binary, one PostgreSQL, config via env vars,
  migrations embedded. `docker compose up` gives you a running instance.

## What this protects against — and what it doesn't

Honesty is the differentiator, so here it is.

**Protects against:**

- Forged or tampered validation responses — MITM boxes, hostile proxies,
  DNS tricks, TLS-stripping middleware. Signatures verify or they don't.
- Replayed "valid" responses (client nonce echo) and stale responses
  (timestamp echo + configurable skew window).
- License-key theft from a stolen database: only SHA-256 hashes of
  125-bit-entropy keys are stored.
- Forging responses from a stolen database: signing keys in the DB are
  encrypted under `CERBERUS_MASTER_KEY`, which is not in the DB.
- Password-database cracking (argon2id) and offline email enumeration
  (peppered HMAC, not plain hashes).

**Does NOT protect against:**

- **A patched client binary.** If an attacker edits your app to skip the
  license check, no server can stop them. This is true of every licensing
  product ever sold; the ones that claim otherwise are selling obfuscation.
  Signed responses raise the bar from "spoof a server on the LAN" to
  "reverse-engineer and patch each release" — that is the honest ceiling.
- A compromised server or leaked master key. Whoever holds the master key
  can sign anything.
- Key sharing before first use — a key is bearer credential until it binds
  to a HWID on first redemption.
- Denial of service. Admin login is rate-limited per IP (it is the only
  unauthenticated guessing surface); everything else has no limits in v0.1
  (global limiting is scoped for v0.2) — put the server behind a reverse
  proxy with limits. Note the login limiter keys on the TCP peer address,
  so behind a proxy it sees one IP; use the proxy's limiter there.
- Eavesdropping. Signatures give integrity, not confidentiality — run TLS
  (terminate at your proxy) or license keys and HWIDs transit readable.

## Quickstart

```sh
git clone https://github.com/cerberusauth/cerberusauth
cd cerberusauth
docker compose up --build
```

That starts Postgres and the server on `:8080` with a **development** master
key and a bootstrap admin (`admin@example.com` / `change-me-please`). The
compose file sets `CERBERUS_DEV_MODE=true` for exactly this reason: outside
dev mode the server refuses to start with the published dev key, so this
setup cannot silently become a production deployment. For anything beyond
kicking the tires, generate a real key and set real credentials — see
`.env.example`:

```sh
make genkey   # prints a fresh CERBERUS_MASTER_KEY
```

> `CERBERUS_MASTER_KEY` encrypts every app's signing key. Losing it bricks
> signing and logins; leaking it lets the holder forge licenses. Treat it
> like a private key, because it is one.

### Five-minute tour

```sh
# 1. Log in
TOKEN=$(curl -s localhost:8080/v1/admin/login \
  -d '{"email":"admin@example.com","password":"change-me-please"}' | jq -r .token)

# 2. Create an application (returns its public key — pin this in your client)
APP=$(curl -s localhost:8080/v1/admin/apps \
  -H "Authorization: Bearer $TOKEN" -d '{"name":"My Game"}')
APP_ID=$(echo "$APP" | jq -r .id)

# 3. Issue a 30-day license
curl -s "localhost:8080/v1/admin/apps/$APP_ID/licenses" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"count":1,"tier":"pro","duration_seconds":2592000}'
# → {"licenses":[{"key":"P4X7Q-9K2MN-TR8VW-3EZ5H-BC6DF", ...}]}
# The plaintext key appears exactly once. Store it or lose it.

# 4. Redeem it from the client (binds the HWID, starts the 30 days)
curl -s localhost:8080/v1/client/redeem -d '{
  "app_id":"'$APP_ID'",
  "license_key":"P4X7Q-9K2MN-TR8VW-3EZ5H-BC6DF",
  "hwid":"machine-fingerprint-here",
  "nonce":"'$(openssl rand -hex 16)'",
  "timestamp":'$(date +%s)'}'
# → {"alg":"ed25519","key_id":"…","payload":"<base64>","signature":"<base64>"}
```

The client then: decodes `payload`, verifies `signature` over those exact
bytes with the pinned public key, parses the JSON, checks `nonce` equals the
one it just sent, checks `valid`. In that order. `POST /v1/client/validate`
is the same shape for every subsequent startup check.

## Configuration

Everything is an environment variable. See [.env.example](.env.example) for
the annotated list: `CERBERUS_DATABASE_URL`, `CERBERUS_MASTER_KEY`,
`CERBERUS_LISTEN_ADDR`, `CERBERUS_CLOCK_SKEW`, `CERBERUS_ADMIN_TOKEN_TTL`,
`CERBERUS_AUTO_MIGRATE`, `CERBERUS_BOOTSTRAP_ADMIN_EMAIL/_PASSWORD`,
`CERBERUS_DEV_MODE`.

## Development

```sh
make build     # → bin/cerberusd
make test      # unit tests; no database required
make run       # needs CERBERUS_DATABASE_URL + CERBERUS_MASTER_KEY
make migrate
```

Design and protocol details live in [ARCHITECTURE.md](ARCHITECTURE.md).

## Testing

Three layers, cheapest first:

1. **Unit tests** — `make test` (or `go test ./...`). No database, no
   network: the service and HTTP layers run against an in-memory store
   fake. Covers the crypto (sign/verify, tamper rejection, key encryption),
   key generation/canonicalization, argon2id, the full license state
   machine, replay/skew handling, and an end-to-end HTTP test that drives
   every endpoint and verifies real signatures.

2. **Live smoke test** — boot the real thing (`docker compose up --build`,
   or any Postgres + `make run`) and walk the [five-minute tour](#five-minute-tour)
   above with curl.

3. **Client-side verification** — [examples/client-verify](examples/client-verify/main.go)
   is a reference client: it sends a validation request, verifies the
   Ed25519 signature over the raw payload bytes, and checks the nonce echo —
   the exact sequence every real client must implement. Point it at a
   running server:

   ```sh
   go run ./examples/client-verify \
     -app    <app uuid> \
     -pubkey <base64 public key from app creation> \
     -key    XXXXX-XXXXX-XXXXX-XXXXX-XXXXX \
     -hwid   my-device-1 \
     -redeem   # first run only; drop for subsequent validations
   ```

   Feed it the wrong `-pubkey` and watch it refuse — that refusal is the
   entire security model working.

## Roadmap

- v0.2 — dashboard UI, client SDKs (verify-then-parse reference
  implementations), global rate limiting (login is already limited), audit
  log, key rotation, expired-token cleanup job.
- v0.3 — per-app end-user accounts, resellers, webhooks.

Not planned, ever: proprietary "pro" tiers, license servers you can't run
yourself, features that only work against a hosted instance.

## License

Apache-2.0. See [LICENSE](LICENSE).
