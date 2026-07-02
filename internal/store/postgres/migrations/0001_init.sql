-- CerberusAuth v0.1 initial schema.
--
-- Hashing policy (see ARCHITECTURE.md):
--   license keys  -> SHA-256 of canonical form (plaintext never stored)
--   admin emails  -> HMAC-SHA-256 peppered with the master key
--   admin tokens  -> SHA-256
--   HWIDs         -> SHA-256

CREATE TABLE applications (
    id              uuid PRIMARY KEY,
    name            text NOT NULL,
    public_key      bytea NOT NULL,      -- raw Ed25519 public key (32 bytes)
    private_key_enc bytea NOT NULL,      -- Ed25519 private key, AES-256-GCM under CERBERUS_MASTER_KEY
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE licenses (
    id               uuid PRIMARY KEY,
    app_id           uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    key_hash         bytea NOT NULL UNIQUE,
    key_hint         text NOT NULL,      -- last key group, for admin listings
    tier             text NOT NULL DEFAULT 'default',
    status           text NOT NULL DEFAULT 'issued'
                     CHECK (status IN ('issued', 'active', 'banned')),
    ban_reason       text,
    duration_seconds bigint,             -- relative expiry; clock starts at redemption
    expires_at       timestamptz,        -- absolute expiry; NULL = perpetual
    hwid_hash        bytea,              -- bound device; NULL = unbound
    redeemed_at      timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX licenses_app_id_idx ON licenses (app_id);

CREATE TABLE admin_users (
    id            uuid PRIMARY KEY,
    email_hash    bytea NOT NULL UNIQUE,
    password_hash text NOT NULL,         -- argon2id, PHC string
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE admin_tokens (
    id         uuid PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Expired-token cleanup job will want this. TODO(v0.2): the cleanup job.
CREATE INDEX admin_tokens_expires_at_idx ON admin_tokens (expires_at);

-- TODO(v0.2): audit_log table.
-- TODO(v0.3): end_users (per-app user accounts), resellers, webhooks.
