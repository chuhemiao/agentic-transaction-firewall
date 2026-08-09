-- DS-030: support organization-scoped first-destination queries over the
-- versioned Payment Profile EIP-155 normalized key and prior permitted
-- Decisions.

CREATE INDEX audit_events_permitted_first_destination_idx
    ON audit_events (
        organization_id,
        (canonical_event #>> '{data,binding,profile,id}'),
        (canonical_event #>> '{data,binding,profile,version}'),
        (lower(canonical_event #>> '{data,binding,execution_constraints,destination}')),
        occurred_at DESC,
        sequence DESC
    )
    WHERE event_type = 'DecisionRecorded'
      AND canonical_event -> 'data' ->> 'decision' = 'PERMIT'
      AND canonical_event -> 'data' -> 'binding' IS NOT NULL;

UPDATE atf_schema_metadata
SET schema_version = 13,
    minimum_reader_version = 13,
    minimum_writer_version = 13,
    installed_at = statement_timestamp()
WHERE component = 'durable_state';
