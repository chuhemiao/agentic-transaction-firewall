-- DS-029: support bounded organization/Agent daily cumulative-spend
-- aggregates over prior permitted Decisions.

CREATE INDEX audit_events_permitted_daily_spend_idx
    ON audit_events (
        organization_id,
        (canonical_event -> 'data' ->> 'agent_id'),
        occurred_at DESC,
        sequence DESC,
        (canonical_event #>> '{data,binding,execution_constraints,asset}')
    )
    WHERE event_type = 'DecisionRecorded'
      AND canonical_event -> 'data' ->> 'decision' = 'PERMIT';

UPDATE atf_schema_metadata
SET schema_version = 12,
    minimum_reader_version = 12,
    minimum_writer_version = 12,
    installed_at = statement_timestamp()
WHERE component = 'durable_state';
