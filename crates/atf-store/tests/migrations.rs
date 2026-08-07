use sqlx::{
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
    assert_eq!(schema.minimum_reader_version, 1);
    assert_eq!(schema.minimum_writer_version, 1);

    let second_run = atf_store::migrate_pool(&pool).await?;
    assert_eq!(second_run, schema);
    let migration_count: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await?;
    assert_eq!(migration_count, 1);

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
              'decisions',
              'audit_chain_heads',
              'audit_events'
          )
        "#,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(table_count, 7);

    let store = atf_store::Store::connect(&database_url).await?;
    assert_eq!(store.schema(), schema);
    assert!(!store.is_closed());
    store.close().await;

    sqlx::query(
        "UPDATE atf_schema_metadata SET schema_version = 2 WHERE component = 'durable_state'",
    )
    .execute(&pool)
    .await?;
    let incompatible = atf_store::Store::connect(&database_url)
        .await
        .expect_err("a newer database schema must fail closed");
    assert!(matches!(
        incompatible,
        atf_store::StoreError::IncompatibleSchema {
            binary_version: 1,
            database_version: 2,
            minimum_reader_version: 1,
            minimum_writer_version: 1,
        }
    ));
    sqlx::query(
        "UPDATE atf_schema_metadata SET schema_version = 1 WHERE component = 'durable_state'",
    )
    .execute(&pool)
    .await?;

    seed_organizations(&pool).await?;
    insert_intent(&pool, "org-a", "intent-a", "shared-key", HASH_A).await?;
    insert_intent(&pool, "org-b", "intent-b", "shared-key", HASH_B).await?;

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
            expires_at
        ) VALUES ($1, $2, $3, '1.0', '{}'::jsonb, $4, $5, now(), now() + interval '5 minutes')
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
    assert_sqlstate(&truncate, "55000");

    sqlx::query("RESET ROLE").execute(&mut *connection).await?;
    let event_count: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events")
        .fetch_one(&mut *connection)
        .await?;
    assert_eq!(event_count, 1);

    Ok(())
}
