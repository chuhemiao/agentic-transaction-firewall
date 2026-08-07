-- Add the durable idempotency binding and evaluator-fencing record required
-- by ADR-0002. NEW is an admission outcome, not a persisted state: a committed
-- reservation is either being evaluated or is immutably completed.

CREATE TABLE idempotency_reservations (
    organization_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    intent_id TEXT NOT NULL,
    intent_hash atf_sha256_hex NOT NULL,
    state TEXT NOT NULL,
    lease_owner TEXT NOT NULL,
    lease_generation BIGINT NOT NULL,
    lease_expires_at TIMESTAMPTZ NOT NULL,
    result_evaluation_id TEXT,
    result_decision_id TEXT,
    result_decision_hash atf_sha256_hex,
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    completed_at TIMESTAMPTZ,
    PRIMARY KEY (organization_id, idempotency_key),
    UNIQUE (organization_id, intent_id),
    FOREIGN KEY (organization_id)
        REFERENCES organizations (organization_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, intent_id, intent_hash)
        REFERENCES intents (organization_id, intent_id, intent_hash)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (
        organization_id,
        result_decision_id,
        intent_id,
        result_evaluation_id
    ) REFERENCES decisions (
        organization_id,
        decision_id,
        intent_id,
        evaluation_id
    ) ON DELETE RESTRICT,
    FOREIGN KEY (
        organization_id,
        result_decision_id,
        result_decision_hash
    ) REFERENCES decisions (
        organization_id,
        decision_id,
        decision_hash
    ) ON DELETE RESTRICT,
    CHECK (
        idempotency_key = btrim(idempotency_key)
        AND char_length(idempotency_key) BETWEEN 1 AND 255
    ),
    CHECK (intent_id = btrim(intent_id) AND char_length(intent_id) BETWEEN 1 AND 128),
    CHECK (state IN ('IN_PROGRESS', 'COMPLETED')),
    CHECK (
        lease_owner = btrim(lease_owner)
        AND char_length(lease_owner) BETWEEN 1 AND 128
        AND lease_owner ~ '^[A-Za-z0-9._:-]+$'
    ),
    CHECK (lease_generation > 0),
    CHECK (
        (
            state = 'IN_PROGRESS'
            AND result_evaluation_id IS NULL
            AND result_decision_id IS NULL
            AND result_decision_hash IS NULL
            AND completed_at IS NULL
        )
        OR (
            state = 'COMPLETED'
            AND result_evaluation_id IS NOT NULL
            AND result_decision_id IS NOT NULL
            AND result_decision_hash IS NOT NULL
            AND completed_at IS NOT NULL
        )
    )
);

CREATE INDEX idempotency_reservations_recovery_idx
    ON idempotency_reservations (
        organization_id,
        lease_expires_at,
        idempotency_key
    )
    WHERE state = 'IN_PROGRESS';

DO $$
BEGIN
    IF EXISTS (
        SELECT organization_id, intent_id
        FROM decisions
        GROUP BY organization_id, intent_id
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION 'cannot backfill idempotency from ambiguous Decisions'
            USING ERRCODE = '23514';
    END IF;
END;
$$;

-- Existing completed records remain completed and bind to their immutable
-- result. Existing unfinished admissions receive an already-expired lease;
-- DS-013 must recover them through the fenced, fail-closed path rather than
-- silently evaluating with current inputs.
INSERT INTO idempotency_reservations (
    organization_id,
    idempotency_key,
    intent_id,
    intent_hash,
    state,
    lease_owner,
    lease_generation,
    lease_expires_at,
    result_evaluation_id,
    result_decision_id,
    result_decision_hash,
    created_at,
    updated_at,
    completed_at
)
SELECT
    intent.organization_id,
    intent.idempotency_key,
    intent.intent_id,
    intent.intent_hash,
    CASE WHEN decision.decision_id IS NULL THEN 'IN_PROGRESS' ELSE 'COMPLETED' END,
    'migration-0003',
    1,
    statement_timestamp(),
    decision.evaluation_id,
    decision.decision_id,
    decision.decision_hash,
    intent.received_at,
    COALESCE(decision.recorded_at, statement_timestamp()),
    decision.recorded_at
FROM intents AS intent
LEFT JOIN decisions AS decision
  ON decision.organization_id = intent.organization_id
 AND decision.intent_id = intent.intent_id;

CREATE FUNCTION protect_idempotency_reservation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'idempotency_reservations cannot be deleted'
            USING ERRCODE = '55000';
    END IF;

    IF OLD.state = 'COMPLETED' THEN
        RAISE EXCEPTION 'completed idempotency reservations are immutable'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
       OR NEW.intent_id IS DISTINCT FROM OLD.intent_id
       OR NEW.intent_hash IS DISTINCT FROM OLD.intent_hash THEN
        RAISE EXCEPTION 'idempotency reservation bindings are immutable'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.lease_generation < OLD.lease_generation THEN
        RAISE EXCEPTION 'idempotency lease generation cannot decrease'
            USING ERRCODE = '55000';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER idempotency_reservations_protect_update_delete
    BEFORE UPDATE OR DELETE ON idempotency_reservations
    FOR EACH ROW
    EXECUTE FUNCTION protect_idempotency_reservation();

CREATE FUNCTION reject_idempotency_reservation_truncate()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'idempotency_reservations cannot be truncated'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER idempotency_reservations_reject_truncate
    BEFORE TRUNCATE ON idempotency_reservations
    FOR EACH STATEMENT
    EXECUTE FUNCTION reject_idempotency_reservation_truncate();

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM atf_schema_metadata
        WHERE component = 'durable_state'
          AND schema_version = 2
          AND minimum_reader_version = 2
          AND minimum_writer_version = 2
    ) THEN
        RAISE EXCEPTION 'unexpected durable-state schema metadata before migration 0003'
            USING ERRCODE = '55000';
    END IF;

    UPDATE atf_schema_metadata
    SET
        schema_version = 3,
        minimum_reader_version = 3,
        minimum_writer_version = 3,
        installed_at = statement_timestamp()
    WHERE component = 'durable_state';
END;
$$;
