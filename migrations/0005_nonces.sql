-- DS-016 authenticated admission. A committed identity Nonce is immutable,
-- Agent-scoped and bound to one exact request/idempotency tuple plus the
-- IdentityVerified event that proved consumption. Raw Nonces and signatures
-- are never stored.

ALTER TABLE idempotency_reservations
    ADD CONSTRAINT idempotency_reservations_full_binding_unique
        UNIQUE (organization_id, idempotency_key, intent_id, intent_hash);

CREATE TABLE identity_nonces (
    organization_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    nonce_hash atf_sha256_hex NOT NULL,
    key_id TEXT NOT NULL,
    intent_id TEXT NOT NULL,
    intent_hash atf_sha256_hex NOT NULL,
    idempotency_key TEXT NOT NULL,
    envelope_hash atf_sha256_hex NOT NULL,
    envelope_expires_at TIMESTAMPTZ NOT NULL,
    agent_lifecycle_version BIGINT NOT NULL,
    agent_record_hash atf_sha256_hex NOT NULL,
    key_lifecycle_version BIGINT NOT NULL,
    key_record_hash atf_sha256_hex NOT NULL,
    verified_event_id TEXT NOT NULL,
    consumed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (organization_id, agent_id, nonce_hash),
    FOREIGN KEY (organization_id, agent_id)
        REFERENCES agents (organization_id, agent_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, agent_id, key_id)
        REFERENCES identity_keys (organization_id, agent_id, key_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, intent_id, intent_hash)
        REFERENCES intents (organization_id, intent_id, intent_hash)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (organization_id, idempotency_key, intent_id, intent_hash)
        REFERENCES idempotency_reservations (
            organization_id,
            idempotency_key,
            intent_id,
            intent_hash
        )
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (organization_id, verified_event_id)
        REFERENCES audit_events (organization_id, event_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (agent_id = btrim(agent_id) AND char_length(agent_id) BETWEEN 1 AND 128),
    CHECK (key_id = btrim(key_id) AND char_length(key_id) BETWEEN 1 AND 128),
    CHECK (intent_id = btrim(intent_id) AND char_length(intent_id) BETWEEN 1 AND 128),
    CHECK (
        idempotency_key = btrim(idempotency_key)
        AND char_length(idempotency_key) BETWEEN 1 AND 255
    ),
    CHECK (agent_lifecycle_version > 0),
    CHECK (key_lifecycle_version > 0),
    CHECK (
        verified_event_id = btrim(verified_event_id)
        AND char_length(verified_event_id) BETWEEN 1 AND 128
    ),
    CHECK (consumed_at < envelope_expires_at)
);

CREATE INDEX identity_nonces_intent_idx
    ON identity_nonces (organization_id, intent_id, consumed_at DESC);

CREATE INDEX identity_nonces_expiry_idx
    ON identity_nonces (organization_id, envelope_expires_at);

CREATE FUNCTION reject_identity_nonce_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'identity nonces are immutable'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER identity_nonces_reject_update_delete
    BEFORE UPDATE OR DELETE ON identity_nonces
    FOR EACH ROW
    EXECUTE FUNCTION reject_identity_nonce_mutation();

CREATE TRIGGER identity_nonces_reject_truncate
    BEFORE TRUNCATE ON identity_nonces
    FOR EACH STATEMENT
    EXECUTE FUNCTION reject_identity_nonce_mutation();

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM atf_schema_metadata
        WHERE component = 'durable_state'
          AND schema_version = 4
          AND minimum_reader_version = 4
          AND minimum_writer_version = 4
    ) THEN
        RAISE EXCEPTION 'unexpected durable-state schema metadata before migration 0005'
            USING ERRCODE = '55000';
    END IF;

    UPDATE atf_schema_metadata
    SET
        schema_version = 5,
        minimum_reader_version = 5,
        minimum_writer_version = 5,
        installed_at = statement_timestamp()
    WHERE component = 'durable_state';
END;
$$;
