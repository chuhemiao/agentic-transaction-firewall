-- Durable Shadow base schema. Cross-table transaction APIs and concurrent
-- chain append behavior are implemented in DS-003/DS-004.

CREATE DOMAIN atf_sha256_hex AS TEXT
    CHECK (VALUE ~ '^[0-9a-f]{64}$');

CREATE TABLE atf_schema_metadata (
    component TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    minimum_reader_version INTEGER NOT NULL CHECK (minimum_reader_version > 0),
    minimum_writer_version INTEGER NOT NULL CHECK (minimum_writer_version > 0),
    installed_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    CHECK (minimum_reader_version <= schema_version),
    CHECK (minimum_writer_version <= schema_version)
);

INSERT INTO atf_schema_metadata (
    component,
    schema_version,
    minimum_reader_version,
    minimum_writer_version
) VALUES ('durable_state', 1, 1, 1);

CREATE TABLE organizations (
    organization_id TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    CHECK (
        organization_id = btrim(organization_id)
        AND char_length(organization_id) BETWEEN 1 AND 128
    )
);

CREATE TABLE intents (
    organization_id TEXT NOT NULL,
    intent_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    spec_version TEXT NOT NULL,
    canonical_intent JSONB NOT NULL,
    canonical_intent_bytes BYTEA NOT NULL,
    intent_hash atf_sha256_hex NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (organization_id, intent_id),
    UNIQUE (organization_id, idempotency_key),
    UNIQUE (organization_id, intent_id, intent_hash),
    FOREIGN KEY (organization_id)
        REFERENCES organizations (organization_id)
        ON DELETE RESTRICT,
    CHECK (intent_id = btrim(intent_id) AND char_length(intent_id) BETWEEN 1 AND 128),
    CHECK (
        idempotency_key = btrim(idempotency_key)
        AND char_length(idempotency_key) BETWEEN 1 AND 255
    ),
    CHECK (spec_version = btrim(spec_version) AND char_length(spec_version) BETWEEN 1 AND 32),
    CHECK (jsonb_typeof(canonical_intent) = 'object'),
    CHECK (octet_length(canonical_intent_bytes) > 0)
);

CREATE TABLE evaluations (
    organization_id TEXT NOT NULL,
    evaluation_id TEXT NOT NULL,
    intent_id TEXT NOT NULL,
    canonical_evaluation JSONB NOT NULL,
    canonical_evaluation_bytes BYTEA NOT NULL,
    evaluation_hash atf_sha256_hex NOT NULL,
    evaluated_at TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (organization_id, evaluation_id),
    UNIQUE (organization_id, evaluation_id, intent_id),
    UNIQUE (organization_id, evaluation_id, evaluation_hash),
    FOREIGN KEY (organization_id, intent_id)
        REFERENCES intents (organization_id, intent_id)
        ON DELETE RESTRICT,
    CHECK (
        evaluation_id = btrim(evaluation_id)
        AND char_length(evaluation_id) BETWEEN 1 AND 128
    ),
    CHECK (jsonb_typeof(canonical_evaluation) = 'object'),
    CHECK (octet_length(canonical_evaluation_bytes) > 0)
);

CREATE TABLE decisions (
    organization_id TEXT NOT NULL,
    decision_id TEXT NOT NULL,
    intent_id TEXT NOT NULL,
    evaluation_id TEXT NOT NULL,
    canonical_decision JSONB NOT NULL,
    canonical_decision_bytes BYTEA NOT NULL,
    decision_hash atf_sha256_hex NOT NULL,
    decided_at TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (organization_id, decision_id),
    UNIQUE (organization_id, evaluation_id),
    UNIQUE (organization_id, decision_id, intent_id, evaluation_id),
    UNIQUE (organization_id, decision_id, decision_hash),
    FOREIGN KEY (organization_id, intent_id)
        REFERENCES intents (organization_id, intent_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, evaluation_id, intent_id)
        REFERENCES evaluations (organization_id, evaluation_id, intent_id)
        ON DELETE RESTRICT,
    CHECK (decision_id = btrim(decision_id) AND char_length(decision_id) BETWEEN 1 AND 128),
    CHECK (jsonb_typeof(canonical_decision) = 'object'),
    CHECK (octet_length(canonical_decision_bytes) > 0)
);

CREATE TABLE audit_chain_heads (
    organization_id TEXT PRIMARY KEY,
    last_sequence BIGINT NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    last_event_hash atf_sha256_hex,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    FOREIGN KEY (organization_id)
        REFERENCES organizations (organization_id)
        ON DELETE RESTRICT,
    CHECK (
        (last_sequence = 0 AND last_event_hash IS NULL)
        OR (last_sequence > 0 AND last_event_hash IS NOT NULL)
    )
);

CREATE TABLE audit_events (
    organization_id TEXT NOT NULL,
    sequence BIGINT NOT NULL CHECK (sequence > 0),
    event_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    occurred_at TIMESTAMPTZ NOT NULL,
    intent_id TEXT,
    evaluation_id TEXT,
    decision_id TEXT,
    previous_event_hash atf_sha256_hex,
    event_hash atf_sha256_hex NOT NULL,
    canonical_event JSONB NOT NULL,
    canonical_event_bytes BYTEA NOT NULL,
    inserted_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (organization_id, sequence),
    UNIQUE (organization_id, event_id),
    UNIQUE (organization_id, event_hash),
    FOREIGN KEY (organization_id)
        REFERENCES organizations (organization_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, intent_id)
        REFERENCES intents (organization_id, intent_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, evaluation_id, intent_id)
        REFERENCES evaluations (organization_id, evaluation_id, intent_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, decision_id, intent_id, evaluation_id)
        REFERENCES decisions (organization_id, decision_id, intent_id, evaluation_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, previous_event_hash)
        REFERENCES audit_events (organization_id, event_hash)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY IMMEDIATE,
    CHECK (event_id = btrim(event_id) AND char_length(event_id) BETWEEN 1 AND 128),
    CHECK (event_type = btrim(event_type) AND char_length(event_type) BETWEEN 1 AND 128),
    CHECK (evaluation_id IS NULL OR intent_id IS NOT NULL),
    CHECK (decision_id IS NULL OR (intent_id IS NOT NULL AND evaluation_id IS NOT NULL)),
    CHECK (
        (sequence = 1 AND previous_event_hash IS NULL)
        OR (sequence > 1 AND previous_event_hash IS NOT NULL)
    ),
    CHECK (previous_event_hash IS NULL OR previous_event_hash <> event_hash),
    CHECK (jsonb_typeof(canonical_event) = 'object'),
    CHECK (octet_length(canonical_event_bytes) > 0)
);

CREATE INDEX intents_received_at_idx
    ON intents (organization_id, received_at DESC);

CREATE INDEX evaluations_intent_idx
    ON evaluations (organization_id, intent_id, evaluated_at DESC);

CREATE INDEX decisions_intent_idx
    ON decisions (organization_id, intent_id, decided_at DESC);

CREATE INDEX audit_events_intent_idx
    ON audit_events (organization_id, intent_id, sequence)
    WHERE intent_id IS NOT NULL;

CREATE INDEX audit_events_type_time_idx
    ON audit_events (organization_id, event_type, occurred_at DESC);

CREATE FUNCTION reject_audit_event_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER audit_events_reject_update_delete
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW
    EXECUTE FUNCTION reject_audit_event_mutation();

CREATE TRIGGER audit_events_reject_truncate
    BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT
    EXECUTE FUNCTION reject_audit_event_mutation();
