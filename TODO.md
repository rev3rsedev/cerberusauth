# Go-public checklist (v0.1 → first push)

State when this list was written (2026-07-02): MVP complete and working.
50 unit tests green, live smoke test passed against a real Postgres 18
(server booted, full lifecycle driven over HTTP, Ed25519 envelopes verified
with the reference client, wrong-pubkey correctly rejected). What remains is
release hygiene, not product work. Delete this file when it's done.

Machine notes for whoever picks this up: Go 1.26.4 lives at
`C:\Program Files\Go\bin\go.exe` (new shells may need the full path).
Docker Desktop is NOT installed. Repo is NOT git-initialized yet.

## Blockers — do these before the repo goes public

- [x] **1. GitHub home DECIDED 2026-07-02: personal account —
  `github.com/rev3rsedev/cerberusauth`.** Research that informed it:
  - GitHub orgs `cerberusauth` AND `cerberus-auth` are TAKEN (both private,
    zero public repos — squatted/dormant; verified via API, org id
    110757349 for the first).
  - Free handles checked: `cerberuslicensing`, `cerberus-licensing`,
    `getcerberus`, `cerberuskey`, `cerberus-keys`. Taken: `cerberusd`.
  - Name space is crowded: Nike-Inc/cerberus (secure property store with
    auth), nefarioustim/cerberus-auth (Python auth microservice),
    snapp-incubator/Cerberus (Envoy auth), pyeve/cerberus (validation),
    Cerberus FTP Server (commercial, Redwood). USPTO has multiple live
    CERBERUS registrations incl. Searchlight Cyber LLC #7363526
    (cybersecurity software, reg. 2024) — closest adjacency for a
    security-positioned project. Not legal advice; renaming is cheapest
    right now if wanted (module rename pending anyway).
  - Options: (a) personal account `github.com/<you>/cerberusauth`;
    (b) keep product name, free org like `getcerberus`;
    (c) rename project entirely.

- [x] **2. Module path renamed — DONE 2026-07-02** to
  `github.com/rev3rsedev/cerberusauth`: go.mod, 16 .go files, README clone
  URL. Build + tests green after.

- [x] **3. git init + initial commit — DONE 2026-07-02.** `.gitattributes`
  (`* text=auto eol=lf`) added first, `.claude/settings.local.json`
  ignored, `git init -b main`, root commit e64041b (44 files). Tag
  `v0.1.0` after the public push, not before — still open.

- [ ] **4. Verify the Docker quickstart actually works.** README promises
  `docker compose up --build` → running instance. Never tested — Docker
  isn't installed on this machine. Install Docker Desktop (or test in CI,
  item 5) and run the README five-minute tour against the compose stack
  verbatim. Fix whatever breaks (suspect areas: none known, it's just
  untested).

- [ ] **5. CI — GitHub Actions.** One workflow: `gofmt -l` (fail if
  output), `go vet ./...`, `go test ./...`, `docker build .`. Optional
  second job: Postgres service container + a store integration test gated
  on `CERBERUS_TEST_DATABASE_URL` (test doesn't exist yet — small, covers
  internal/store/postgres against a real DB). Add the badge to README.

- [x] **6. SECURITY.md — DONE 2026-07-02.** GitHub private vulnerability
  reporting as the channel (no email published — add one later if wanted),
  in/out of scope mirrors the README threat model (client patching, DoS
  stance, dev-mode sandboxes out), honest solo-maintainer response times
  (ack 7d, assessment 30d), coordinated disclosure with credit.

- [x] **7. HKDF key split — DONE 2026-07-02.** `signing.DeriveKeys` expands
  the master key via HKDF-SHA256 (stdlib `crypto/hkdf`, not x/crypto — it's
  in std since Go 1.24) into the AES key (info `cerberus/enc-v1`) and email
  pepper (info `cerberus/email-v1`). Service holds the derived keys; the raw
  master never touches a primitive. Known-answer test pins the derivation so
  a refactor can't silently orphan stored data. ARCHITECTURE.md updated.

## Should-fix — public scrutiny will find these (judgment calls)

- [x] **8. Rate-limit `/v1/admin/login` — DONE 2026-07-02.** Per-IP lazy
  token bucket (burst 5, one attempt per 10s) in
  internal/server/ratelimit.go, wrapping only the login route. Keyed on
  RemoteAddr, deliberately not X-Forwarded-For (spoofable); behind a proxy,
  limit at the proxy — comment in clientIP explains. Idle buckets swept
  opportunistically. 429 + Retry-After. Unit + integration tests.

- [x] **9. Logout / token revocation — DONE 2026-07-02.**
  `DELETE /v1/admin/token` revokes the presenting token (204; idempotent at
  the service level). `DeleteAdminToken` store method in postgres + fake;
  the postgres one also sweeps already-expired rows in the same statement
  (uses admin_tokens_expires_at_idx). Real cleanup job stays TODO(v0.2).

- [x] **10. Dev-key tripwire — DONE 2026-07-02.** Posture chosen: fail
  closed. `serve` and `create-admin` refuse the published dev key unless
  `CERBERUS_DEV_MODE=true`; even in dev mode a loud warning is logged.
  Compose sets `CERBERUS_DEV_MODE: "true"` so the quickstart stays
  one-command. Detection in config.MasterKeyIsDevKey, gate in
  cmd/cerberusd guardMasterKey. README + .env.example document it.

## Nice-to-have — fine to ship without

- [x] CONTRIBUTING.md — DONE 2026-07-02 (build/test, PR expectations,
  what won't merge). PR/issue templates still open, fine to ship without.
- [x] Postgres integration test — DONE 2026-07-02:
  internal/store/postgres/postgres_test.go, gated on
  CERBERUS_TEST_DATABASE_URL, truncates tables, covers CRUD + redeem race
  semantics + expired-token sweep. CI integration job runs it.
- [x] README badges (CI, license, Go version) — DONE 2026-07-02. CI badge
  goes live after first push to GitHub.
- [ ] GitHub release notes for v0.1.0.

## Context that survives the chat

- Testing story (the "how do I test this" answer) is documented in
  README.md → Testing section: unit tests need no DB;
  examples/client-verify is the reference client and doubles as the
  signature-verification demo (feed it a wrong -pubkey to see rejection).
- Design decisions and their reasoning: ARCHITECTURE.md → Decision log.
  Don't re-litigate pgx/stdlib-mux/own-migrator without new evidence.
- Protocol invariant to never break: clients verify the signature over the
  exact transported payload bytes BEFORE parsing; failures are signed too;
  reason strings are API (see internal/service/payload.go constants).
