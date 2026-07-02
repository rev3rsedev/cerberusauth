-- Move per-app signing keys out of applications into their own table so an
-- app can hold several: exactly one active (signs everything), the rest
-- retired but still listed for clients that pinned them before a rotation.

CREATE TABLE app_keys (
    id              uuid        PRIMARY KEY,
    app_id          uuid        NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    public_key      bytea       NOT NULL,
    private_key_enc bytea       NOT NULL,
    active          boolean     NOT NULL,
    created_at      timestamptz NOT NULL,
    retired_at      timestamptz
);

-- One active key per app, enforced by the database, not just the code.
CREATE UNIQUE INDEX app_keys_one_active_idx ON app_keys (app_id) WHERE active;
CREATE INDEX app_keys_app_idx ON app_keys (app_id, created_at DESC);

-- Adopt the existing single key of every app as its active key.
INSERT INTO app_keys (id, app_id, public_key, private_key_enc, active, created_at)
SELECT gen_random_uuid(), id, public_key, private_key_enc, true, created_at
FROM applications;

ALTER TABLE applications
    DROP COLUMN public_key,
    DROP COLUMN private_key_enc;
