-- DS-018 PostgreSQL-authoritative Operator subjects and organization roles.
-- Raw external subjects and bearer credentials never enter durable state.

CREATE TABLE operator_subjects (
    operator_id TEXT PRIMARY KEY,
    issuer_id TEXT NOT NULL,
    subject_fingerprint atf_sha256_hex NOT NULL,
    principal_kind TEXT NOT NULL,
    status TEXT NOT NULL,
    audit_organization_id TEXT NOT NULL,
    canonical_record JSONB NOT NULL,
    canonical_record_bytes BYTEA NOT NULL,
    record_hash atf_sha256_hex NOT NULL,
    lifecycle_version BIGINT NOT NULL,
    last_event_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (issuer_id, subject_fingerprint),
    FOREIGN KEY (audit_organization_id)
        REFERENCES organizations (organization_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (audit_organization_id, last_event_id)
        REFERENCES audit_events (organization_id, event_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (operator_id = btrim(operator_id) AND char_length(operator_id) BETWEEN 1 AND 128),
    CHECK (issuer_id = btrim(issuer_id) AND char_length(issuer_id) BETWEEN 1 AND 128),
    CHECK (principal_kind IN ('HUMAN', 'SERVICE')),
    CHECK (status IN ('ACTIVE', 'DISABLED')),
    CHECK (jsonb_typeof(canonical_record) = 'object'),
    CHECK (octet_length(canonical_record_bytes) > 0),
    CHECK (lifecycle_version > 0),
    CHECK (last_event_id = btrim(last_event_id) AND char_length(last_event_id) BETWEEN 1 AND 128),
    CHECK (updated_at >= created_at)
);

CREATE TABLE operator_roles (
    operator_id TEXT NOT NULL,
    organization_id TEXT NOT NULL,
    role TEXT NOT NULL,
    status TEXT NOT NULL,
    canonical_binding JSONB NOT NULL,
    canonical_binding_bytes BYTEA NOT NULL,
    binding_hash atf_sha256_hex NOT NULL,
    lifecycle_version BIGINT NOT NULL,
    last_event_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (operator_id, organization_id, role),
    FOREIGN KEY (operator_id)
        REFERENCES operator_subjects (operator_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (organization_id)
        REFERENCES organizations (organization_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, last_event_id)
        REFERENCES audit_events (organization_id, event_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (role IN ('org_admin', 'policy_author', 'approver', 'auditor')),
    CHECK (status IN ('ACTIVE', 'REVOKED')),
    CHECK (jsonb_typeof(canonical_binding) = 'object'),
    CHECK (octet_length(canonical_binding_bytes) > 0),
    CHECK (lifecycle_version > 0),
    CHECK (last_event_id = btrim(last_event_id) AND char_length(last_event_id) BETWEEN 1 AND 128),
    CHECK (updated_at >= created_at)
);

CREATE INDEX operator_roles_authorization_idx
    ON operator_roles (organization_id, operator_id, status, role);

CREATE FUNCTION protect_operator_subject_lifecycle()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'operator subjects cannot be deleted'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.operator_id IS DISTINCT FROM OLD.operator_id
       OR NEW.issuer_id IS DISTINCT FROM OLD.issuer_id
       OR NEW.subject_fingerprint IS DISTINCT FROM OLD.subject_fingerprint
       OR NEW.principal_kind IS DISTINCT FROM OLD.principal_kind
       OR NEW.audit_organization_id IS DISTINCT FROM OLD.audit_organization_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR (NEW.canonical_record - 'status') IS DISTINCT FROM (OLD.canonical_record - 'status') THEN
        RAISE EXCEPTION 'operator subject bindings are immutable'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.status = OLD.status
       OR NEW.lifecycle_version <> OLD.lifecycle_version + 1
       OR NEW.last_event_id = OLD.last_event_id
       OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'invalid operator subject lifecycle transition'
            USING ERRCODE = '55000';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER operator_subjects_protect_update_delete
    BEFORE UPDATE OR DELETE ON operator_subjects
    FOR EACH ROW
    EXECUTE FUNCTION protect_operator_subject_lifecycle();

CREATE FUNCTION protect_operator_role_lifecycle()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'operator roles cannot be deleted'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.operator_id IS DISTINCT FROM OLD.operator_id
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.role IS DISTINCT FROM OLD.role
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR (NEW.canonical_binding - 'status') IS DISTINCT FROM (OLD.canonical_binding - 'status') THEN
        RAISE EXCEPTION 'operator role bindings are immutable'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.status = OLD.status
       OR NEW.lifecycle_version <> OLD.lifecycle_version + 1
       OR NEW.last_event_id = OLD.last_event_id
       OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'invalid operator role lifecycle transition'
            USING ERRCODE = '55000';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER operator_roles_protect_update_delete
    BEFORE UPDATE OR DELETE ON operator_roles
    FOR EACH ROW
    EXECUTE FUNCTION protect_operator_role_lifecycle();

CREATE FUNCTION reject_operator_rbac_truncate()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'operator RBAC tables cannot be truncated'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER operator_subjects_reject_truncate
    BEFORE TRUNCATE ON operator_subjects
    FOR EACH STATEMENT
    EXECUTE FUNCTION reject_operator_rbac_truncate();

CREATE TRIGGER operator_roles_reject_truncate
    BEFORE TRUNCATE ON operator_roles
    FOR EACH STATEMENT
    EXECUTE FUNCTION reject_operator_rbac_truncate();

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM atf_schema_metadata
        WHERE component = 'durable_state'
          AND schema_version = 5
          AND minimum_reader_version = 5
          AND minimum_writer_version = 5
    ) THEN
        RAISE EXCEPTION 'unexpected durable-state schema metadata before migration 0006'
            USING ERRCODE = '55000';
    END IF;

    UPDATE atf_schema_metadata
    SET
        schema_version = 6,
        minimum_reader_version = 6,
        minimum_writer_version = 6,
        installed_at = statement_timestamp()
    WHERE component = 'durable_state';
END;
$$;
