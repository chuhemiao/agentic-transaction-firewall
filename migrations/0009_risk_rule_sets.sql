-- DS-026 immutable Risk Rule Set artifacts for deterministic Original Replay.

CREATE TABLE risk_rule_sets (
    organization_id TEXT NOT NULL,
    environment TEXT NOT NULL,
    engine_version TEXT NOT NULL,
    rule_set_version TEXT NOT NULL,
    rule_set_hash atf_sha256_hex NOT NULL,
    canonical_rule_set JSONB NOT NULL,
    canonical_rule_set_bytes BYTEA NOT NULL,
    artifact_hash atf_sha256_hex NOT NULL,
    installed_by_operator_id TEXT NOT NULL,
    installed_event_id TEXT NOT NULL,
    installed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (
        organization_id, environment, engine_version, rule_set_version
    ),
    UNIQUE (organization_id, environment, rule_set_hash),
    UNIQUE (
        organization_id, environment, engine_version,
        rule_set_version, rule_set_hash
    ),
    FOREIGN KEY (organization_id)
        REFERENCES organizations (organization_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (installed_by_operator_id)
        REFERENCES operator_subjects (operator_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, installed_event_id)
        REFERENCES audit_events (organization_id, event_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (environment ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    CHECK (engine_version ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    CHECK (
        rule_set_version = btrim(rule_set_version)
        AND char_length(rule_set_version) BETWEEN 1 AND 64
    ),
    CHECK (jsonb_typeof(canonical_rule_set) = 'object'),
    CHECK (
        octet_length(canonical_rule_set_bytes) > 0
        AND octet_length(canonical_rule_set_bytes) <= 65536
    ),
    CHECK (
        installed_event_id = btrim(installed_event_id)
        AND char_length(installed_event_id) BETWEEN 1 AND 128
    )
);

CREATE FUNCTION protect_risk_rule_set_artifacts()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'installed Risk Rule Sets are immutable'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER risk_rule_sets_protect_mutation
    BEFORE UPDATE OR DELETE ON risk_rule_sets
    FOR EACH ROW
    EXECUTE FUNCTION protect_risk_rule_set_artifacts();

CREATE TRIGGER risk_rule_sets_reject_truncate
    BEFORE TRUNCATE ON risk_rule_sets
    FOR EACH STATEMENT
    EXECUTE FUNCTION protect_risk_rule_set_artifacts();

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM atf_schema_metadata
        WHERE component = 'durable_state'
          AND schema_version = 8
          AND minimum_reader_version = 8
          AND minimum_writer_version = 8
    ) THEN
        RAISE EXCEPTION 'unexpected durable-state schema metadata before migration 0009'
            USING ERRCODE = '55000';
    END IF;

    UPDATE atf_schema_metadata
    SET
        schema_version = 9,
        minimum_reader_version = 9,
        minimum_writer_version = 9,
        installed_at = statement_timestamp()
    WHERE component = 'durable_state';
END;
$$;
