-- DS-020 signed immutable Policy Bundle artifacts and audited active pointers.
-- Publisher private keys are never accepted or persisted.

CREATE TABLE policy_bundles (
    organization_id TEXT NOT NULL,
    environment TEXT NOT NULL,
    bundle_id TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    bundle_hash atf_sha256_hex NOT NULL,
    activates_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    artifact_bytes BYTEA NOT NULL,
    artifact_hash atf_sha256_hex NOT NULL,
    publisher_key_id TEXT NOT NULL,
    publisher_public_key BYTEA NOT NULL,
    publisher_public_key_hash atf_sha256_hex NOT NULL,
    signature BYTEA NOT NULL,
    installed_by_operator_id TEXT NOT NULL,
    installed_event_id TEXT NOT NULL,
    installed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (organization_id, environment, bundle_id, policy_version),
    UNIQUE (organization_id, environment, bundle_hash),
    UNIQUE (organization_id, environment, bundle_id, policy_version, bundle_hash),
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
    CHECK (bundle_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    CHECK (policy_version = btrim(policy_version) AND char_length(policy_version) BETWEEN 1 AND 64),
    CHECK (expires_at > activates_at),
    CHECK (octet_length(artifact_bytes) > 0 AND octet_length(artifact_bytes) <= 17891328),
    CHECK (publisher_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    CHECK (octet_length(publisher_public_key) = 32),
    CHECK (octet_length(signature) = 64),
    CHECK (installed_event_id = btrim(installed_event_id) AND char_length(installed_event_id) BETWEEN 1 AND 128)
);

CREATE TABLE active_policy_bundles (
    organization_id TEXT NOT NULL,
    environment TEXT NOT NULL,
    bundle_id TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    bundle_hash atf_sha256_hex NOT NULL,
    previous_policy_version TEXT,
    previous_bundle_hash atf_sha256_hex,
    lifecycle_version BIGINT NOT NULL,
    last_event_id TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (organization_id, environment, bundle_id),
    FOREIGN KEY (organization_id, environment, bundle_id, policy_version, bundle_hash)
        REFERENCES policy_bundles (
            organization_id, environment, bundle_id, policy_version, bundle_hash
        )
        ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, environment, bundle_id, previous_policy_version, previous_bundle_hash)
        REFERENCES policy_bundles (
            organization_id, environment, bundle_id, policy_version, bundle_hash
        )
        ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, last_event_id)
        REFERENCES audit_events (organization_id, event_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CHECK ((previous_policy_version IS NULL) = (previous_bundle_hash IS NULL)),
    CHECK (previous_bundle_hash IS NULL OR previous_bundle_hash <> bundle_hash),
    CHECK (lifecycle_version > 0),
    CHECK (last_event_id = btrim(last_event_id) AND char_length(last_event_id) BETWEEN 1 AND 128)
);

CREATE INDEX active_policy_bundles_scope_idx
    ON active_policy_bundles (organization_id, environment, bundle_id);

CREATE FUNCTION protect_policy_bundle_artifacts()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'installed Policy Bundles are immutable'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER policy_bundles_protect_mutation
    BEFORE UPDATE OR DELETE ON policy_bundles
    FOR EACH ROW
    EXECUTE FUNCTION protect_policy_bundle_artifacts();

CREATE FUNCTION protect_active_policy_pointer()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'active Policy Bundle pointers cannot be deleted'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.environment IS DISTINCT FROM OLD.environment
       OR NEW.bundle_id IS DISTINCT FROM OLD.bundle_id
       OR NEW.lifecycle_version <> OLD.lifecycle_version + 1
       OR NEW.bundle_hash = OLD.bundle_hash
       OR NEW.previous_policy_version IS DISTINCT FROM OLD.policy_version
       OR NEW.previous_bundle_hash IS DISTINCT FROM OLD.bundle_hash
       OR NEW.last_event_id = OLD.last_event_id
       OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'invalid active Policy Bundle pointer transition'
            USING ERRCODE = '55000';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER active_policy_bundles_protect_mutation
    BEFORE UPDATE OR DELETE ON active_policy_bundles
    FOR EACH ROW
    EXECUTE FUNCTION protect_active_policy_pointer();

CREATE FUNCTION reject_policy_bundle_truncate()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'Policy Bundle tables cannot be truncated'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER policy_bundles_reject_truncate
    BEFORE TRUNCATE ON policy_bundles
    FOR EACH STATEMENT
    EXECUTE FUNCTION reject_policy_bundle_truncate();

CREATE TRIGGER active_policy_bundles_reject_truncate
    BEFORE TRUNCATE ON active_policy_bundles
    FOR EACH STATEMENT
    EXECUTE FUNCTION reject_policy_bundle_truncate();

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM atf_schema_metadata
        WHERE component = 'durable_state'
          AND schema_version = 6
          AND minimum_reader_version = 6
          AND minimum_writer_version = 6
    ) THEN
        RAISE EXCEPTION 'unexpected durable-state schema metadata before migration 0007'
            USING ERRCODE = '55000';
    END IF;

    UPDATE atf_schema_metadata
    SET
        schema_version = 7,
        minimum_reader_version = 7,
        minimum_writer_version = 7,
        installed_at = statement_timestamp()
    WHERE component = 'durable_state';
END;
$$;
