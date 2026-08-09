use sqlx::{
    migrate::Migrate,
    postgres::{PgConnectOptions, PgPoolOptions},
    ConnectOptions, Connection, Executor, PgConnection, PgPool,
};
use std::{
    env,
    error::Error,
    process,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const HASH_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const HASH_D: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

#[tokio::test]
async fn clean_database_migration_enforces_tenant_and_append_only_invariants(
) -> Result<(), Box<dyn Error>> {
    let admin_url = env::var("ATF_TEST_DATABASE_URL").expect(
        "ATF_TEST_DATABASE_URL must point to a PostgreSQL database where the test may create databases and roles",
    );
    let admin_options = PgConnectOptions::from_str(&admin_url)?;
    let suffix = unique_suffix();
    let database_name = format!("atf_ds002_{suffix}");
    let role_name = format!("atf_app_{suffix}");
    let quoted_database = quote_identifier(&database_name);
    let quoted_role = quote_identifier(&role_name);

    let mut admin = PgConnection::connect_with(&admin_options).await?;
    admin
        .execute(format!("CREATE DATABASE {quoted_database}").as_str())
        .await?;
    admin
        .execute(format!("CREATE ROLE {quoted_role} NOLOGIN").as_str())
        .await?;

    let database_options = admin_options.clone().database(&database_name);
    let database_url = database_options.to_url_lossy().to_string();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(database_options)
        .await?;

    let missing = atf_store::verify_schema(&pool)
        .await
        .expect_err("an unmigrated database must fail closed");
    assert!(matches!(
        missing,
        atf_store::StoreError::MissingSchemaMetadata
    ));

    let schema = atf_store::migrate_pool(&pool).await?;
    assert_eq!(schema.schema_version, atf_store::CURRENT_SCHEMA_VERSION);
    assert_eq!(schema.minimum_reader_version, 13);
    assert_eq!(schema.minimum_writer_version, 13);

    let second_run = atf_store::migrate_pool(&pool).await?;
    assert_eq!(second_run, schema);
    let migration_count: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await?;
    assert_eq!(migration_count, 13);

    let history_index_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_indexes WHERE schemaname = 'public' AND indexname = 'audit_events_permitted_purchase_history_idx'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(history_index_count, 1);
    let daily_spend_index_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_indexes WHERE schemaname = 'public' AND indexname = 'audit_events_permitted_daily_spend_idx'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(daily_spend_index_count, 1);
    let first_destination_index_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_indexes WHERE schemaname = 'public' AND indexname = 'audit_events_permitted_first_destination_idx'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(first_destination_index_count, 1);

    let lifecycle_columns: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*)
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'intents'
          AND column_name IN (
              'lifecycle_state',
              'lifecycle_version',
              'lifecycle_contract_version',
              'lifecycle_event_id',
              'lifecycle_updated_at'
          )
        "#,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(lifecycle_columns, 5);

    let table_count: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*)
        FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_name IN (
              'atf_schema_metadata',
              'organizations',
              'intents',
              'evaluations',
              'evaluation_contexts',
              'decisions',
              'idempotency_reservations',
              'audit_chain_heads',
              'audit_events',
              'agents',
              'identity_keys',
              'identity_nonces',
              'operator_subjects',
              'operator_roles',
              'policy_bundles',
              'active_policy_bundles',
              'risk_rule_sets',
              'counterfactual_replays'
          )
        "#,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(table_count, 18);

    let nonce_guard_count: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*)
        FROM information_schema.triggers
        WHERE event_object_schema = 'public'
          AND event_object_table = 'identity_nonces'
          AND trigger_name IN (
              'identity_nonces_reject_update_delete',
              'identity_nonces_reject_truncate'
          )
        "#,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(nonce_guard_count, 2);

    let operator_guard_count: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*)
        FROM information_schema.triggers
        WHERE event_object_schema = 'public'
          AND event_object_table IN ('operator_subjects', 'operator_roles')
          AND trigger_name IN (
              'operator_subjects_protect_update_delete',
              'operator_subjects_reject_truncate',
              'operator_roles_protect_update_delete',
              'operator_roles_reject_truncate'
          )
        "#,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(operator_guard_count, 4);

    let policy_guard_count: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*)
        FROM information_schema.triggers
        WHERE event_object_schema = 'public'
          AND event_object_table IN ('policy_bundles', 'active_policy_bundles')
          AND trigger_name IN (
              'policy_bundles_protect_mutation',
              'policy_bundles_reject_truncate',
              'active_policy_bundles_protect_mutation',
              'active_policy_bundles_reject_truncate'
          )
        "#,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(policy_guard_count, 4);

    let evaluation_context_guard_count: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*)
        FROM information_schema.triggers
        WHERE event_object_schema = 'public'
          AND event_object_table = 'evaluation_contexts'
          AND trigger_name IN (
              'evaluation_contexts_protect_mutation',
              'evaluation_contexts_reject_truncate'
          )
        "#,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(evaluation_context_guard_count, 2);

    let risk_rule_set_guard_count: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*)
        FROM information_schema.triggers
        WHERE event_object_schema = 'public'
          AND event_object_table = 'risk_rule_sets'
          AND trigger_name IN (
              'risk_rule_sets_protect_mutation',
              'risk_rule_sets_reject_truncate'
          )
        "#,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(risk_rule_set_guard_count, 2);

    let counterfactual_guard_count: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*)
        FROM information_schema.triggers
        WHERE event_object_schema = 'public'
          AND event_object_table = 'counterfactual_replays'
          AND trigger_name IN (
              'counterfactual_replays_protect_mutation',
              'counterfactual_replays_reject_truncate'
          )
        "#,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(counterfactual_guard_count, 2);

    let store = atf_store::Store::connect(&database_url).await?;
    assert_eq!(store.schema(), schema);
    assert!(!store.is_closed());
    store.close().await;

    sqlx::query(
        "UPDATE atf_schema_metadata SET schema_version = 14 WHERE component = 'durable_state'",
    )
    .execute(&pool)
    .await?;
    let incompatible = atf_store::Store::connect(&database_url)
        .await
        .expect_err("a newer database schema must fail closed");
    assert!(matches!(
        incompatible,
        atf_store::StoreError::IncompatibleSchema {
            binary_version: 13,
            database_version: 14,
            minimum_reader_version: 13,
            minimum_writer_version: 13,
        }
    ));
    sqlx::query(
        "UPDATE atf_schema_metadata SET schema_version = 13 WHERE component = 'durable_state'",
    )
    .execute(&pool)
    .await?;

    seed_organizations(&pool).await?;
    insert_intent(&pool, "org-a", "intent-a", "shared-key", HASH_A).await?;
    insert_intent(&pool, "org-b", "intent-b", "shared-key", HASH_B).await?;

    let invalid_lifecycle = sqlx::query(
        "UPDATE intents SET lifecycle_state = 'NOT_A_STATE' WHERE organization_id = 'org-a' AND intent_id = 'intent-a'",
    )
    .execute(&pool)
    .await
    .expect_err("unknown lifecycle states must fail closed at the schema boundary");
    assert_sqlstate(&invalid_lifecycle, "23514");

    let invalid_version = sqlx::query(
        "UPDATE intents SET lifecycle_version = 0 WHERE organization_id = 'org-a' AND intent_id = 'intent-a'",
    )
    .execute(&pool)
    .await
    .expect_err("lifecycle versions must stay positive");
    assert_sqlstate(&invalid_version, "23514");

    let duplicate_key = insert_intent(&pool, "org-a", "intent-c", "shared-key", HASH_C)
        .await
        .expect_err("same-organization idempotency keys must be unique");
    assert_sqlstate(&duplicate_key, "23505");

    let invalid_hash = insert_intent(&pool, "org-a", "intent-c", "new-key", "NOT-A-HASH")
        .await
        .expect_err("hashes must be lowercase SHA-256 hex");
    assert_sqlstate(&invalid_hash, "23514");

    let cross_tenant_evaluation = insert_evaluation(&pool, "org-b", "eval-cross", "intent-a")
        .await
        .expect_err("an evaluation cannot reference another organization's Intent");
    assert_sqlstate(&cross_tenant_evaluation, "23503");

    insert_intent(&pool, "org-a", "intent-c", "new-key", HASH_C).await?;
    insert_evaluation(&pool, "org-a", "eval-a", "intent-a").await?;

    let mismatched_decision = insert_decision(&pool, "org-a", "decision-bad", "intent-c", "eval-a")
        .await
        .expect_err("a Decision's Intent and Evaluation must match");
    assert_sqlstate(&mismatched_decision, "23503");

    insert_decision(&pool, "org-a", "decision-a", "intent-a", "eval-a").await?;

    let cross_tenant_event = insert_audit_event(
        &pool,
        "org-b",
        "event-cross",
        "intent-a",
        "eval-a",
        "decision-a",
    )
    .await
    .expect_err("Audit evidence cannot reference another organization's records");
    assert_sqlstate(&cross_tenant_event, "23503");

    insert_audit_event(
        &pool,
        "org-a",
        "event-a",
        "intent-a",
        "eval-a",
        "decision-a",
    )
    .await?;

    sqlx::query(
        r#"
        INSERT INTO audit_chain_heads (organization_id, last_sequence, last_event_hash)
        VALUES ('org-a', 1, $1)
        "#,
    )
    .bind(HASH_D)
    .execute(&pool)
    .await?;

    assert_app_role_cannot_mutate_audit(&pool, &quoted_role).await?;

    pool.close().await;
    admin
        .execute(format!("DROP DATABASE {quoted_database}").as_str())
        .await?;
    admin
        .execute(format!("DROP ROLE {quoted_role}").as_str())
        .await?;

    Ok(())
}

#[tokio::test]
async fn lifecycle_migration_backfills_legacy_rows_without_rewriting_canonical_bytes(
) -> Result<(), Box<dyn Error>> {
    let admin_url = env::var("ATF_TEST_DATABASE_URL").expect(
        "ATF_TEST_DATABASE_URL must point to a PostgreSQL database where the test may create databases",
    );
    let admin_options = PgConnectOptions::from_str(&admin_url)?;
    let database_name = format!("atf_ds007_legacy_{}", unique_suffix());
    let quoted_database = quote_identifier(&database_name);
    let mut admin = PgConnection::connect_with(&admin_options).await?;
    admin
        .execute(format!("CREATE DATABASE {quoted_database}").as_str())
        .await?;

    let database_options = admin_options.clone().database(&database_name);
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(database_options.clone())
        .await?;
    let migrator = sqlx::migrate!("../../migrations");
    let mut connection = PgConnection::connect_with(&database_options).await?;
    connection.ensure_migrations_table().await?;
    connection
        .apply(
            migrator
                .iter()
                .find(|migration| migration.version == 1)
                .expect("migration 0001 is embedded"),
        )
        .await?;

    sqlx::query("INSERT INTO organizations (organization_id) VALUES ('legacy-org')")
        .execute(&pool)
        .await?;
    let canonical_bytes = br#"{"legacy":true}"#.to_vec();
    sqlx::query(
        r#"
        INSERT INTO intents (
            organization_id, intent_id, idempotency_key, spec_version,
            canonical_intent, canonical_intent_bytes, intent_hash,
            created_at, expires_at, received_at
        ) VALUES (
            'legacy-org', 'legacy-intent', 'legacy-idem', '1.0',
            '{"legacy": true}'::jsonb, $1, $2,
            '2026-08-08T00:00:00Z', '2026-08-08T00:05:00Z',
            '2026-08-08T00:00:01Z'
        )
        "#,
    )
    .bind(&canonical_bytes)
    .bind(HASH_A)
    .execute(&pool)
    .await?;

    sqlx::query(
        r#"
        INSERT INTO intents (
            organization_id, intent_id, idempotency_key, spec_version,
            canonical_intent, canonical_intent_bytes, intent_hash,
            created_at, expires_at, received_at
        ) VALUES (
            'legacy-org', 'legacy-completed', 'legacy-completed-idem', '1.0',
            '{"legacy": "completed"}'::jsonb, $1, $2,
            '2026-08-08T00:00:00Z', '2026-08-08T00:05:00Z',
            '2026-08-08T00:00:01Z'
        )
        "#,
    )
    .bind(br#"{"legacy":"completed"}"#.as_slice())
    .bind(HASH_D)
    .execute(&pool)
    .await?;
    insert_evaluation(&pool, "legacy-org", "legacy-evaluation", "legacy-completed").await?;
    sqlx::query(
        r#"
        INSERT INTO decisions (
            organization_id, decision_id, intent_id, evaluation_id,
            canonical_decision, canonical_decision_bytes, decision_hash,
            decided_at
        ) VALUES (
            'legacy-org', 'legacy-decision', 'legacy-completed',
            'legacy-evaluation', '{"decision": "PERMIT"}'::jsonb,
            $1, $2, '2026-08-08T00:00:02Z'
        )
        "#,
    )
    .bind(br#"{"decision":"PERMIT"}"#.as_slice())
    .bind(HASH_C)
    .execute(&pool)
    .await?;

    connection
        .apply(
            migrator
                .iter()
                .find(|migration| migration.version == 2)
                .expect("migration 0002 is embedded"),
        )
        .await?;

    let row: (String, i64, i32, Option<String>, Vec<u8>) = sqlx::query_as(
        r#"
        SELECT lifecycle_state, lifecycle_version, lifecycle_contract_version,
               lifecycle_event_id, canonical_intent_bytes
        FROM intents
        WHERE organization_id = 'legacy-org' AND intent_id = 'legacy-intent'
        "#,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(row.0, "RECEIVED");
    assert_eq!(row.1, 1);
    assert_eq!(row.2, 0);
    assert_eq!(row.3, None);
    assert_eq!(row.4, canonical_bytes);

    connection
        .apply(
            migrator
                .iter()
                .find(|migration| migration.version == 3)
                .expect("migration 0003 is embedded"),
        )
        .await?;

    let reservation: (String, i64, bool, Vec<u8>) = sqlx::query_as(
        r#"
        SELECT
            reservation.state,
            reservation.lease_generation,
            reservation.lease_expires_at <= clock_timestamp(),
            intent.canonical_intent_bytes
        FROM idempotency_reservations AS reservation
        JOIN intents AS intent
          ON intent.organization_id = reservation.organization_id
         AND intent.intent_id = reservation.intent_id
        WHERE reservation.organization_id = 'legacy-org'
          AND reservation.idempotency_key = 'legacy-idem'
        "#,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(reservation.0, "IN_PROGRESS");
    assert_eq!(reservation.1, 1);
    assert!(reservation.2, "unfinished legacy work must be expired");
    assert_eq!(reservation.3, canonical_bytes);

    let completed: (String, String, String, String) = sqlx::query_as(
        r#"
        SELECT
            state,
            result_evaluation_id,
            result_decision_id,
            result_decision_hash::text
        FROM idempotency_reservations
        WHERE organization_id = 'legacy-org'
          AND idempotency_key = 'legacy-completed-idem'
        "#,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        completed,
        (
            "COMPLETED".into(),
            "legacy-evaluation".into(),
            "legacy-decision".into(),
            HASH_C.into(),
        )
    );
    let version_before_identity: i32 = sqlx::query_scalar(
        "SELECT schema_version FROM atf_schema_metadata WHERE component = 'durable_state'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(version_before_identity, 3);

    connection
        .apply(
            migrator
                .iter()
                .find(|migration| migration.version == 4)
                .expect("migration 0004 is embedded"),
        )
        .await?;
    let canonical_bytes_after_identity: Vec<u8> = sqlx::query_scalar(
        "SELECT canonical_intent_bytes FROM intents WHERE organization_id = 'legacy-org' AND intent_id = 'legacy-intent'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(canonical_bytes_after_identity, canonical_bytes);
    let identity_table_count: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*)
        FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_name IN ('agents', 'identity_keys')
        "#,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(identity_table_count, 2);
    let version_before_nonces: i32 = sqlx::query_scalar(
        "SELECT schema_version FROM atf_schema_metadata WHERE component = 'durable_state'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(version_before_nonces, 4);

    connection
        .apply(
            migrator
                .iter()
                .find(|migration| migration.version == 5)
                .expect("migration 0005 is embedded"),
        )
        .await?;
    let canonical_bytes_after_nonces: Vec<u8> = sqlx::query_scalar(
        "SELECT canonical_intent_bytes FROM intents WHERE organization_id = 'legacy-org' AND intent_id = 'legacy-intent'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(canonical_bytes_after_nonces, canonical_bytes);
    connection
        .apply(
            migrator
                .iter()
                .find(|migration| migration.version == 6)
                .expect("migration 0006 is embedded"),
        )
        .await?;
    connection
        .apply(
            migrator
                .iter()
                .find(|migration| migration.version == 7)
                .expect("migration 0007 is embedded"),
        )
        .await?;
    connection
        .apply(
            migrator
                .iter()
                .find(|migration| migration.version == 8)
                .expect("migration 0008 is embedded"),
        )
        .await?;
    connection
        .apply(
            migrator
                .iter()
                .find(|migration| migration.version == 9)
                .expect("migration 0009 is embedded"),
        )
        .await?;
    connection
        .apply(
            migrator
                .iter()
                .find(|migration| migration.version == 10)
                .expect("migration 0010 is embedded"),
        )
        .await?;
    connection
        .apply(
            migrator
                .iter()
                .find(|migration| migration.version == 11)
                .expect("migration 0011 is embedded"),
        )
        .await?;
    connection
        .apply(
            migrator
                .iter()
                .find(|migration| migration.version == 12)
                .expect("migration 0012 is embedded"),
        )
        .await?;
    connection
        .apply(
            migrator
                .iter()
                .find(|migration| migration.version == 13)
                .expect("migration 0013 is embedded"),
        )
        .await?;
    assert_eq!(atf_store::verify_schema(&pool).await?.schema_version, 13);
    let nonce_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM identity_nonces")
        .fetch_one(&pool)
        .await?;
    assert_eq!(nonce_rows, 0);

    connection.close().await?;
    pool.close().await;
    admin
        .execute(format!("DROP DATABASE {quoted_database}").as_str())
        .await?;
    Ok(())
}

fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after Unix epoch")
        .as_nanos();
    format!("{}_{nanos}", process::id())
}

fn quote_identifier(identifier: &str) -> String {
    assert!(
        identifier
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_'),
        "test-generated PostgreSQL identifiers must be alphanumeric"
    );
    format!("\"{identifier}\"")
}

fn assert_sqlstate(error: &sqlx::Error, expected: &str) {
    let actual = error
        .as_database_error()
        .and_then(|database_error| database_error.code())
        .map(|code| code.into_owned());
    assert_eq!(
        actual.as_deref(),
        Some(expected),
        "unexpected error: {error}"
    );
}

async fn seed_organizations(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO organizations (organization_id) VALUES ('org-a'), ('org-b')")
        .execute(pool)
        .await?;
    Ok(())
}

async fn insert_intent(
    pool: &PgPool,
    organization_id: &str,
    intent_id: &str,
    idempotency_key: &str,
    intent_hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO intents (
            organization_id,
            intent_id,
            idempotency_key,
            spec_version,
            canonical_intent,
            canonical_intent_bytes,
            intent_hash,
            created_at,
            expires_at,
            lifecycle_state,
            lifecycle_version,
            lifecycle_contract_version,
            lifecycle_event_id,
            lifecycle_updated_at
        ) VALUES (
            $1, $2, $3, '1.0', '{}'::jsonb, $4, $5,
            now(), now() + interval '5 minutes',
            'RECEIVED', 1, 0, NULL, now()
        )
        "#,
    )
    .bind(organization_id)
    .bind(intent_id)
    .bind(idempotency_key)
    .bind(b"{}".as_slice())
    .bind(intent_hash)
    .execute(pool)
    .await?;
    Ok(())
}

async fn insert_evaluation(
    pool: &PgPool,
    organization_id: &str,
    evaluation_id: &str,
    intent_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO evaluations (
            organization_id,
            evaluation_id,
            intent_id,
            canonical_evaluation,
            canonical_evaluation_bytes,
            evaluation_hash,
            evaluated_at
        ) VALUES ($1, $2, $3, '{}'::jsonb, $4, $5, now())
        "#,
    )
    .bind(organization_id)
    .bind(evaluation_id)
    .bind(intent_id)
    .bind(b"{}".as_slice())
    .bind(HASH_B)
    .execute(pool)
    .await?;
    Ok(())
}

async fn insert_decision(
    pool: &PgPool,
    organization_id: &str,
    decision_id: &str,
    intent_id: &str,
    evaluation_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO decisions (
            organization_id,
            decision_id,
            intent_id,
            evaluation_id,
            canonical_decision,
            canonical_decision_bytes,
            decision_hash,
            decided_at
        ) VALUES ($1, $2, $3, $4, '{}'::jsonb, $5, $6, now())
        "#,
    )
    .bind(organization_id)
    .bind(decision_id)
    .bind(intent_id)
    .bind(evaluation_id)
    .bind(b"{}".as_slice())
    .bind(HASH_C)
    .execute(pool)
    .await?;
    Ok(())
}

async fn insert_audit_event(
    pool: &PgPool,
    organization_id: &str,
    event_id: &str,
    intent_id: &str,
    evaluation_id: &str,
    decision_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO audit_events (
            organization_id,
            sequence,
            event_id,
            event_type,
            schema_version,
            occurred_at,
            intent_id,
            evaluation_id,
            decision_id,
            previous_event_hash,
            event_hash,
            canonical_event,
            canonical_event_bytes
        ) VALUES ($1, 1, $2, 'DecisionRecorded', 1, now(), $3, $4, $5, NULL, $6, '{}'::jsonb, $7)
        "#,
    )
    .bind(organization_id)
    .bind(event_id)
    .bind(intent_id)
    .bind(evaluation_id)
    .bind(decision_id)
    .bind(HASH_D)
    .bind(b"{}".as_slice())
    .execute(pool)
    .await?;
    Ok(())
}

async fn assert_app_role_cannot_mutate_audit(
    pool: &PgPool,
    quoted_role: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(&format!("GRANT USAGE ON SCHEMA public TO {quoted_role}"))
        .execute(pool)
        .await?;
    sqlx::query(&format!(
        "GRANT ALL PRIVILEGES ON TABLE audit_events TO {quoted_role}"
    ))
    .execute(pool)
    .await?;

    let mut connection = pool.acquire().await?;
    sqlx::query(&format!("SET ROLE {quoted_role}"))
        .execute(&mut *connection)
        .await?;

    let update = sqlx::query("UPDATE audit_events SET event_type = 'Changed'")
        .execute(&mut *connection)
        .await
        .expect_err("the application role must not update Audit events");
    assert_sqlstate(&update, "55000");

    let delete = sqlx::query("DELETE FROM audit_events")
        .execute(&mut *connection)
        .await
        .expect_err("the application role must not delete Audit events");
    assert_sqlstate(&delete, "55000");

    let truncate = sqlx::query("TRUNCATE audit_events")
        .execute(&mut *connection)
        .await
        .expect_err("the application role must not truncate Audit events");
    assert_sqlstate_one_of(&truncate, &["55000", "0A000"]);

    sqlx::query("RESET ROLE").execute(&mut *connection).await?;
    let event_count: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events")
        .fetch_one(&mut *connection)
        .await?;
    assert_eq!(event_count, 1);

    Ok(())
}

fn assert_sqlstate_one_of(error: &sqlx::Error, expected: &[&str]) {
    let actual = error
        .as_database_error()
        .and_then(|database_error| database_error.code())
        .map(|code| code.into_owned());
    assert!(
        actual
            .as_deref()
            .is_some_and(|code| expected.contains(&code)),
        "unexpected SQLSTATE for {error}: {actual:?}"
    );
}
