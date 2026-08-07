-- Persist DS-015 Agent and Ed25519 identity-key lifecycle. Every current
-- record points at the organization Audit event committed with that version.

CREATE TABLE agents (
    organization_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    canonical_record JSONB NOT NULL,
    canonical_record_bytes BYTEA NOT NULL,
    record_hash atf_sha256_hex NOT NULL,
    status TEXT NOT NULL,
    lifecycle_version BIGINT NOT NULL,
    last_event_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (organization_id, agent_id),
    FOREIGN KEY (organization_id)
        REFERENCES organizations (organization_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, last_event_id)
        REFERENCES audit_events (organization_id, event_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (agent_id = btrim(agent_id) AND char_length(agent_id) BETWEEN 1 AND 128),
    CHECK (jsonb_typeof(canonical_record) = 'object'),
    CHECK (octet_length(canonical_record_bytes) > 0),
    CHECK (status IN ('ACTIVE', 'SHADOW_ONLY', 'PAUSED', 'REVOKED', 'EXPIRED')),
    CHECK (lifecycle_version > 0),
    CHECK (last_event_id = btrim(last_event_id) AND char_length(last_event_id) BETWEEN 1 AND 128),
    CHECK (expires_at IS NULL OR expires_at > created_at),
    CHECK (updated_at >= created_at)
);

CREATE TABLE identity_keys (
    organization_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    public_key BYTEA NOT NULL,
    public_key_fingerprint atf_sha256_hex NOT NULL,
    canonical_record JSONB NOT NULL,
    canonical_record_bytes BYTEA NOT NULL,
    key_record_hash atf_sha256_hex NOT NULL,
    activates_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    lifecycle_version BIGINT NOT NULL,
    last_event_id TEXT NOT NULL,
    registered_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (organization_id, agent_id, key_id),
    FOREIGN KEY (organization_id, agent_id)
        REFERENCES agents (organization_id, agent_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, last_event_id)
        REFERENCES audit_events (organization_id, event_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (key_id = btrim(key_id) AND char_length(key_id) BETWEEN 1 AND 128),
    CHECK (algorithm = 'ED25519'),
    CHECK (octet_length(public_key) = 32),
    CHECK (jsonb_typeof(canonical_record) = 'object'),
    CHECK (octet_length(canonical_record_bytes) > 0),
    CHECK (expires_at IS NULL OR expires_at > activates_at),
    CHECK (lifecycle_version > 0),
    CHECK (last_event_id = btrim(last_event_id) AND char_length(last_event_id) BETWEEN 1 AND 128),
    CHECK (updated_at >= registered_at)
);

CREATE INDEX agents_status_idx
    ON agents (organization_id, status, updated_at DESC);

CREATE INDEX identity_keys_validity_idx
    ON identity_keys (organization_id, agent_id, activates_at, expires_at, revoked_at);

CREATE FUNCTION protect_agent_lifecycle()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'agents cannot be deleted'
            USING ERRCODE = '55000';
    END IF;

    IF OLD.status IN ('REVOKED', 'EXPIRED') THEN
        RAISE EXCEPTION 'terminal agents are immutable'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.agent_id IS DISTINCT FROM OLD.agent_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
       OR (NEW.canonical_record - 'status') IS DISTINCT FROM (OLD.canonical_record - 'status') THEN
        RAISE EXCEPTION 'agent registration bindings are immutable'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.status = OLD.status
       OR NEW.lifecycle_version <> OLD.lifecycle_version + 1
       OR NEW.last_event_id = OLD.last_event_id
       OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'invalid agent lifecycle transition'
            USING ERRCODE = '55000';
    END IF;

    RETURN NEW;
END;
$$;
CREATE TRIGGER agents_protect_update_delete
    BEFORE UPDATE OR DELETE ON agents
    FOR EACH ROW
    EXECUTE FUNCTION protect_agent_lifecycle();

CREATE FUNCTION protect_identity_key_lifecycle()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'identity keys cannot be deleted'
            USING ERRCODE = '55000';
    END IF;

    IF OLD.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'revoked identity keys are immutable'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.agent_id IS DISTINCT FROM OLD.agent_id
       OR NEW.key_id IS DISTINCT FROM OLD.key_id
       OR NEW.algorithm IS DISTINCT FROM OLD.algorithm
       OR NEW.public_key IS DISTINCT FROM OLD.public_key
       OR NEW.public_key_fingerprint IS DISTINCT FROM OLD.public_key_fingerprint
       OR NEW.activates_at IS DISTINCT FROM OLD.activates_at
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
       OR NEW.registered_at IS DISTINCT FROM OLD.registered_at
       OR (NEW.canonical_record - 'revoked_at') IS DISTINCT FROM (OLD.canonical_record - 'revoked_at') THEN
        RAISE EXCEPTION 'identity key bindings are immutable'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.revoked_at IS NULL
       OR NEW.lifecycle_version <> OLD.lifecycle_version + 1
       OR NEW.last_event_id = OLD.last_event_id
       OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'invalid identity key lifecycle transition'
            USING ERRCODE = '55000';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER identity_keys_protect_update_delete
    BEFORE UPDATE OR DELETE ON identity_keys
    FOR EACH ROW
    EXECUTE FUNCTION protect_identity_key_lifecycle();

CREATE FUNCTION reject_identity_lifecycle_truncate()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'identity lifecycle tables cannot be truncated'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER agents_reject_truncate
    BEFORE TRUNCATE ON agents
    FOR EACH STATEMENT
    EXECUTE FUNCTION reject_identity_lifecycle_truncate();

CREATE TRIGGER identity_keys_reject_truncate
    BEFORE TRUNCATE ON identity_keys
    FOR EACH STATEMENT
    EXECUTE FUNCTION reject_identity_lifecycle_truncate();

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM atf_schema_metadata
        WHERE component = 'durable_state'
          AND schema_version = 3
          AND minimum_reader_version = 3
          AND minimum_writer_version = 3
    ) THEN
        RAISE EXCEPTION 'unexpected durable-state schema metadata before migration 0004'
            USING ERRCODE = '55000';
    END IF;

    UPDATE atf_schema_metadata
    SET
        schema_version = 4,
        minimum_reader_version = 4,
        minimum_writer_version = 4,
        installed_at = statement_timestamp()
    WHERE component = 'durable_state';
END;
$$;
