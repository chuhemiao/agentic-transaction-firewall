-- DS-031: support bounded REQUESTED-event frequency aggregates over the
-- immutable organization/Agent/Profile/action scope attached at admission.

CREATE INDEX audit_events_requested_frequency_idx
    ON audit_events (
        organization_id,
        (canonical_event -> 'data' ->> 'agent_id'),
        (canonical_event #>> '{data,binding,profile,id}'),
        (canonical_event #>> '{data,binding,profile,version}'),
        (canonical_event #>> '{data,binding,action_category}'),
        (canonical_event #>> '{data,binding,action_operation}'),
        occurred_at DESC,
        sequence DESC
    )
    WHERE event_type = 'IntentReceived';

UPDATE atf_schema_metadata
SET schema_version = 14,
    minimum_reader_version = 14,
    minimum_writer_version = 14,
    installed_at = statement_timestamp()
WHERE component = 'durable_state';
