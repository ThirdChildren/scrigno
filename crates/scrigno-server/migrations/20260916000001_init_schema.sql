-- Initial schema, exactly as specified in docs/ARCHITECTURE.md §2.
--
-- Table creation order differs from the doc's prose order (blob before document) only because
-- Postgres requires the referenced table (`blob`) to exist before `document.blob_id` can
-- reference it. No column, constraint or default differs from §2.

CREATE TABLE vault (
    id          uuid PRIMARY KEY,
    singleton   boolean NOT NULL DEFAULT true UNIQUE CHECK (singleton),
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE keyslot (
    id          uuid PRIMARY KEY,
    vault_id    uuid NOT NULL REFERENCES vault(id) ON DELETE CASCADE,
    kind        text NOT NULL CHECK (kind IN ('passphrase', 'recovery')),
    kdf         jsonb NOT NULL,
    wrapped_mk  bytea NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE SEQUENCE document_change_seq;

CREATE TABLE blob (
    id          uuid PRIMARY KEY,
    vault_id    uuid NOT NULL REFERENCES vault(id) ON DELETE CASCADE,
    size        bigint NOT NULL,
    sha256      bytea NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE document (
    id          uuid PRIMARY KEY,
    vault_id    uuid NOT NULL REFERENCES vault(id) ON DELETE CASCADE,
    version     integer NOT NULL CHECK (version >= 1),
    blob_id     uuid REFERENCES blob(id),
    blob_size   bigint NOT NULL DEFAULT 0,
    enc_meta    bytea NOT NULL,
    deleted     boolean NOT NULL DEFAULT false,
    server_seq  bigint NOT NULL UNIQUE,
    updated_at  timestamptz NOT NULL DEFAULT now()
);
