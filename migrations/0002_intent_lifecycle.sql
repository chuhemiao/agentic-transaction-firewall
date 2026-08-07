-- Persist the DS-007 Intent lifecycle materialization without rewriting any
-- immutable canonical document or Audit event. Rows written before this
-- migration remain contract version 0 because their lifecycle evidence was
-- not required to be typed and replayable.

ALTER TABLE intents
    ADD COLUMN lifecycle_state TEXT,
    ADD COLUMN lifecycle_version BIGINT,
    ADD COLUMN lifecycle_contract_version INTEGER,
    ADD COLUMN lifecycle_event_id TEXT,
    ADD COLUMN lifecycle_updated_at TIMESTAMPTZ;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM decisions
        WHERE canonical_decision ->> 'decision' NOT IN ('PERMIT', 'REVIEW', 'DENY', 'ERROR')
           OR canonical_decision ->> 'decision' IS NULL
    ) THEN
        RAISE EXCEPTION 'cannot backfill lifecycle from an unknown canonical Decision kind'
            USING ERRCODE = '23514';
    END IF;
END;
$$;

UPDATE intents AS intent
SET
    lifecycle_state = COALESCE(
        (
            SELECT CASE decision.canonical_decision ->> 'decision'
                WHEN 'PERMIT' THEN 'DECIDED_PERMIT'
                WHEN 'REVIEW' THEN 'DECIDED_REVIEW'
                WHEN 'DENY' THEN 'DECIDED_DENY'
                WHEN 'ERROR' THEN 'DECIDED_ERROR'
            END
            FROM decisions AS decision
            WHERE decision.organization_id = intent.organization_id
              AND decision.intent_id = intent.intent_id
        ),
        'RECEIVED'
    ),
    lifecycle_version = CASE
        WHEN EXISTS (
            SELECT 1
            FROM decisions AS decision
            WHERE decision.organization_id = intent.organization_id
              AND decision.intent_id = intent.intent_id
        ) THEN 2
        ELSE 1
    END,
    lifecycle_contract_version = 0,
    lifecycle_event_id = COALESCE(
        (
            SELECT event.event_id
            FROM audit_events AS event
            WHERE event.organization_id = intent.organization_id
              AND event.intent_id = intent.intent_id
              AND event.event_type = 'DecisionRecorded'
            ORDER BY event.sequence DESC
            LIMIT 1
        ),
        (
            SELECT event.event_id
            FROM audit_events AS event
            WHERE event.organization_id = intent.organization_id
              AND event.intent_id = intent.intent_id
              AND event.event_type = 'IntentReceived'
            ORDER BY event.sequence DESC
            LIMIT 1
        )
    ),
    lifecycle_updated_at = COALESCE(
        (
            SELECT decision.decided_at
            FROM decisions AS decision
            WHERE decision.organization_id = intent.organization_id
              AND decision.intent_id = intent.intent_id
        ),
        intent.received_at
    );

ALTER TABLE intents
    ALTER COLUMN lifecycle_state SET NOT NULL,
    ALTER COLUMN lifecycle_version SET NOT NULL,
    ALTER COLUMN lifecycle_contract_version SET NOT NULL,
    ALTER COLUMN lifecycle_updated_at SET NOT NULL,
    ADD CONSTRAINT intents_lifecycle_state_valid CHECK (
        lifecycle_state IN (
            'RECEIVED',
            'IDENTITY_VERIFIED',
            'IDENTITY_UNVERIFIED',
            'IDENTITY_REJECTED',
            'POLICY_EVALUATED',
            'RISK_EVALUATED',
            'SIMULATION_COMPLETED',
            'DECIDED_PERMIT',
            'DECIDED_REVIEW',
            'DECIDED_DENY',
            'DECIDED_ERROR',
            'APPROVAL_PENDING',
            'APPROVED',
            'REJECTED',
            'EXECUTION_AUTHORIZED',
            'EXECUTION_SUBMITTED',
            'EXECUTION_CONFIRMED',
            'EXECUTION_FAILED',
            'SETTLEMENT_VERIFIED',
            'RECONCILIATION_FAILED',
            'EXPIRED',
            'CANCELLED'
        )
    ),
    ADD CONSTRAINT intents_lifecycle_version_positive CHECK (lifecycle_version > 0),
    ADD CONSTRAINT intents_lifecycle_contract_version_valid CHECK (
        lifecycle_contract_version IN (0, 1)
    ),
    ADD CONSTRAINT intents_lifecycle_event_required CHECK (
        lifecycle_contract_version = 0 OR lifecycle_event_id IS NOT NULL
    ),
    ADD CONSTRAINT intents_lifecycle_event_id_valid CHECK (
        lifecycle_event_id IS NULL
        OR (
            lifecycle_event_id = btrim(lifecycle_event_id)
            AND char_length(lifecycle_event_id) BETWEEN 1 AND 128
        )
    );

ALTER TABLE audit_events
    ADD CONSTRAINT audit_events_intent_event_unique
        UNIQUE (organization_id, event_id, intent_id);

ALTER TABLE intents
    ADD CONSTRAINT intents_lifecycle_event_fk
        FOREIGN KEY (organization_id, lifecycle_event_id, intent_id)
        REFERENCES audit_events (organization_id, event_id, intent_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED;

CREATE INDEX intents_lifecycle_state_idx
    ON intents (organization_id, lifecycle_state, lifecycle_updated_at DESC);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM atf_schema_metadata
        WHERE component = 'durable_state'
          AND schema_version = 1
          AND minimum_reader_version = 1
          AND minimum_writer_version = 1
    ) THEN
        RAISE EXCEPTION 'unexpected durable-state schema metadata before migration 0002'
            USING ERRCODE = '55000';
    END IF;

    UPDATE atf_schema_metadata
    SET
        schema_version = 2,
        minimum_reader_version = 2,
        minimum_writer_version = 2,
        installed_at = statement_timestamp()
    WHERE component = 'durable_state';
END;
$$;
