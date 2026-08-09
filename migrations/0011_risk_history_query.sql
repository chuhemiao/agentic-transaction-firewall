-- DS-028: support bounded duplicate-purchase history snapshots without
-- scanning an organization's complete Audit chain.

CREATE INDEX audit_events_permitted_purchase_history_idx
    ON audit_events (
        organization_id,
        (canonical_event -> 'data' ->> 'agent_id'),
        (canonical_event -> 'data' ->> 'resource_id'),
        occurred_at DESC,
        sequence DESC
    )
    WHERE event_type = 'DecisionRecorded'
      AND canonical_event -> 'data' ->> 'decision' = 'PERMIT';

UPDATE atf_schema_metadata
SET schema_version = 11,
    minimum_reader_version = 11,
    minimum_writer_version = 11,
    installed_at = statement_timestamp()
WHERE component = 'durable_state';
