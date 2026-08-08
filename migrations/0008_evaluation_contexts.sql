-- DS-023 immutable, pre-evaluation input snapshots.

CREATE TABLE evaluation_contexts (
    organization_id TEXT NOT NULL,
    evaluation_id TEXT NOT NULL,
    intent_id TEXT NOT NULL,
    intent_hash atf_sha256_hex NOT NULL,
    evaluation_context_version TEXT NOT NULL,
    environment TEXT NOT NULL,
    canonical_context JSONB NOT NULL,
    canonical_context_bytes BYTEA NOT NULL,
    evaluation_context_hash atf_sha256_hex NOT NULL,
    evaluation_time TIMESTAMPTZ NOT NULL,
    recorded_event_id TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (organization_id, evaluation_id),
    UNIQUE (organization_id, intent_id),
    UNIQUE (
        organization_id,
        evaluation_id,
        intent_id,
        evaluation_context_hash
    ),
    FOREIGN KEY (organization_id, intent_id, intent_hash)
        REFERENCES intents (organization_id, intent_id, intent_hash)
        ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, recorded_event_id)
        REFERENCES audit_events (organization_id, event_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (evaluation_context_version = '1'),
    CHECK (
        evaluation_id = btrim(evaluation_id)
        AND char_length(evaluation_id) BETWEEN 1 AND 128
    ),
    CHECK (
        environment ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$'
    ),
    CHECK (jsonb_typeof(canonical_context) = 'object'),
    CHECK (
        octet_length(canonical_context_bytes) > 0
        AND octet_length(canonical_context_bytes) <= 1048576
    ),
    CHECK (
        recorded_event_id = btrim(recorded_event_id)
        AND char_length(recorded_event_id) BETWEEN 1 AND 128
    )
);

CREATE INDEX evaluation_contexts_intent_idx
    ON evaluation_contexts (organization_id, intent_id, evaluation_time DESC);

ALTER TABLE evaluations
    ADD COLUMN evaluation_context_hash atf_sha256_hex;

ALTER TABLE evaluations
    ADD CONSTRAINT evaluations_evaluation_context_fk
    FOREIGN KEY (
        organization_id,
        evaluation_id,
        intent_id,
        evaluation_context_hash
    ) REFERENCES evaluation_contexts (
        organization_id,
        evaluation_id,
        intent_id,
        evaluation_context_hash
    ) ON DELETE RESTRICT;

CREATE FUNCTION protect_evaluation_contexts()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'Evaluation Context snapshots are immutable'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER evaluation_contexts_protect_mutation
    BEFORE UPDATE OR DELETE ON evaluation_contexts
    FOR EACH ROW
    EXECUTE FUNCTION protect_evaluation_contexts();

CREATE TRIGGER evaluation_contexts_reject_truncate
    BEFORE TRUNCATE ON evaluation_contexts
    FOR EACH STATEMENT
    EXECUTE FUNCTION protect_evaluation_contexts();

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM atf_schema_metadata
        WHERE component = 'durable_state'
          AND schema_version = 7
          AND minimum_reader_version = 7
          AND minimum_writer_version = 7
    ) THEN
        RAISE EXCEPTION 'unexpected durable-state schema metadata before migration 0008'
            USING ERRCODE = '55000';
    END IF;

    UPDATE atf_schema_metadata
    SET
        schema_version = 8,
        minimum_reader_version = 8,
        minimum_writer_version = 8,
        installed_at = statement_timestamp()
    WHERE component = 'durable_state';
END;
$$;
