-- Audit log for admin actions. Append-only: no UPDATE or DELETE path
-- exists in the application, and none should be added. admin_id is a soft
-- reference on purpose: audit history must be able to outlive the admin
-- row it points at.

CREATE TABLE audit_log (
    id        bigserial   PRIMARY KEY,
    at        timestamptz NOT NULL,
    admin_id  uuid,
    action    text        NOT NULL,
    target_id text        NOT NULL DEFAULT '',
    detail    text        NOT NULL DEFAULT ''
);

CREATE INDEX audit_log_at_idx ON audit_log (at DESC, id DESC);
