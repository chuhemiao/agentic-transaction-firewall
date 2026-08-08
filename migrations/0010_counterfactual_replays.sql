-- DS-027 immutable, non-authoritative Counterfactual Replay results.

CREATE TABLE counterfactual_replays (
    organization_id TEXT NOT NULL,
    replay_id TEXT NOT NULL,
    intent_id TEXT NOT NULL,
    original_evaluation_id TEXT NOT NULL,
    original_decision_id TEXT NOT NULL,
    original_decision_hash atf_sha256_hex NOT NULL,
    counterfactual_evaluation_id TEXT NOT NULL,
    counterfactual_decision_id TEXT NOT NULL,
    environment TEXT NOT NULL,
    policy_bundle_id TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    policy_bundle_hash atf_sha256_hex NOT NULL,
    risk_engine_version TEXT NOT NULL,
    risk_rule_set_version TEXT NOT NULL,
    risk_rule_set_hash atf_sha256_hex NOT NULL,
    canonical_context JSONB NOT NULL,
    canonical_context_bytes BYTEA NOT NULL,
    evaluation_context_hash atf_sha256_hex NOT NULL,
    canonical_evaluation JSONB NOT NULL,
    canonical_evaluation_bytes BYTEA NOT NULL,
    evaluation_hash atf_sha256_hex NOT NULL,
    canonical_decision JSONB NOT NULL,
    canonical_decision_bytes BYTEA NOT NULL,
    counterfactual_decision_hash atf_sha256_hex NOT NULL,
    original_outcome TEXT NOT NULL,
    counterfactual_outcome TEXT NOT NULL,
    outcome_changed BOOLEAN NOT NULL,
    authoritative BOOLEAN NOT NULL DEFAULT FALSE,
    requested_by_operator_id TEXT NOT NULL,
    completed_event_id TEXT NOT NULL,
    evaluated_at TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (organization_id, replay_id),
    UNIQUE (organization_id, counterfactual_evaluation_id),
    UNIQUE (organization_id, counterfactual_decision_id),
    FOREIGN KEY (organization_id, intent_id)
        REFERENCES intents (organization_id, intent_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, original_evaluation_id, intent_id)
        REFERENCES evaluations (organization_id, evaluation_id, intent_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (
        organization_id, original_decision_id, intent_id, original_evaluation_id
    ) REFERENCES decisions (
        organization_id, decision_id, intent_id, evaluation_id
    ) ON DELETE RESTRICT,
    FOREIGN KEY (
        organization_id, environment, policy_bundle_id,
        policy_version, policy_bundle_hash
    ) REFERENCES policy_bundles (
        organization_id, environment, bundle_id,
        policy_version, bundle_hash
    ) ON DELETE RESTRICT,
    FOREIGN KEY (
        organization_id, environment, risk_engine_version,
        risk_rule_set_version, risk_rule_set_hash
    ) REFERENCES risk_rule_sets (
        organization_id, environment, engine_version,
        rule_set_version, rule_set_hash
    ) ON DELETE RESTRICT,
    FOREIGN KEY (requested_by_operator_id)
        REFERENCES operator_subjects (operator_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, completed_event_id)
        REFERENCES audit_events (organization_id, event_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (replay_id = btrim(replay_id) AND char_length(replay_id) BETWEEN 1 AND 128),
    CHECK (
        counterfactual_evaluation_id = btrim(counterfactual_evaluation_id)
        AND char_length(counterfactual_evaluation_id) BETWEEN 1 AND 128
        AND counterfactual_evaluation_id <> original_evaluation_id
    ),
    CHECK (
        counterfactual_decision_id = btrim(counterfactual_decision_id)
        AND char_length(counterfactual_decision_id) BETWEEN 1 AND 128
        AND counterfactual_decision_id <> original_decision_id
    ),
    CHECK (environment ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    CHECK (policy_bundle_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    CHECK (policy_version = btrim(policy_version) AND char_length(policy_version) BETWEEN 1 AND 64),
    CHECK (risk_engine_version ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    CHECK (risk_rule_set_version = btrim(risk_rule_set_version) AND char_length(risk_rule_set_version) BETWEEN 1 AND 64),
    CHECK (jsonb_typeof(canonical_context) = 'object'),
    CHECK (octet_length(canonical_context_bytes) BETWEEN 1 AND 1048576),
    CHECK (jsonb_typeof(canonical_evaluation) = 'object'),
    CHECK (octet_length(canonical_evaluation_bytes) BETWEEN 1 AND 1048576),
    CHECK (jsonb_typeof(canonical_decision) = 'object'),
    CHECK (octet_length(canonical_decision_bytes) BETWEEN 1 AND 1048576),
    CHECK (original_outcome IN ('PERMIT', 'REVIEW', 'DENY', 'ERROR')),
    CHECK (counterfactual_outcome IN ('PERMIT', 'REVIEW', 'DENY', 'ERROR')),
    CHECK (outcome_changed = (original_outcome <> counterfactual_outcome)),
    CHECK (authoritative = FALSE),
    CHECK (completed_event_id = btrim(completed_event_id) AND char_length(completed_event_id) BETWEEN 1 AND 128)
);

CREATE INDEX counterfactual_replays_intent_idx
    ON counterfactual_replays (organization_id, intent_id, recorded_at DESC);

CREATE FUNCTION protect_counterfactual_replays()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'Counterfactual Replay records are immutable'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER counterfactual_replays_protect_mutation
    BEFORE UPDATE OR DELETE ON counterfactual_replays
    FOR EACH ROW
    EXECUTE FUNCTION protect_counterfactual_replays();

CREATE TRIGGER counterfactual_replays_reject_truncate
    BEFORE TRUNCATE ON counterfactual_replays
    FOR EACH STATEMENT
    EXECUTE FUNCTION protect_counterfactual_replays();

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM atf_schema_metadata
        WHERE component = 'durable_state'
          AND schema_version = 9
          AND minimum_reader_version = 9
          AND minimum_writer_version = 9
    ) THEN
        RAISE EXCEPTION 'unexpected durable-state schema metadata before migration 0010'
            USING ERRCODE = '55000';
    END IF;

    UPDATE atf_schema_metadata
    SET
        schema_version = 10,
        minimum_reader_version = 10,
        minimum_writer_version = 10,
        installed_at = statement_timestamp()
    WHERE component = 'durable_state';
END;
$$;
