use atf_audit::{EventType, NewAuditEvent};
use atf_core::Timestamp;
use atf_store::{Store, StoreError};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    ConnectOptions, Connection, Executor, PgConnection, PgPool,
};
use std::{
    env,
    error::Error,
    process,
    str::FromStr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Barrier;

const CONCURRENT_WRITERS: usize = 32;

#[tokio::test]
async fn concurrent_same_organization_appends_form_one_linear_chain() -> Result<(), Box<dyn Error>>
{
    let database = TestDatabase::create("concurrent").await?;
    database.seed_organizations(&["org-a"]).await?;
    let store = Store::connect(&database.url).await?;
    let barrier = Arc::new(Barrier::new(CONCURRENT_WRITERS));

    let mut writers = Vec::with_capacity(CONCURRENT_WRITERS);
    for writer in 0..CONCURRENT_WRITERS {
        let store = store.clone();
        let barrier = Arc::clone(&barrier);
        writers.push(tokio::spawn(async move {
            let event = NewAuditEvent::new(
                EventType::KillSwitchTriggered,
                occurred_at(writer),
                None,
                serde_json::json!({"writer": writer}),
            );
            barrier.wait().await;
            store.append_audit_event("org-a", event).await
        }));
    }

    for writer in writers {
        writer.await??;
    }

    let events = store.load_verified_audit_chain("org-a").await?;
    assert_eq!(events.len(), CONCURRENT_WRITERS);
    assert_eq!(
        events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        (1..=CONCURRENT_WRITERS as i64).collect::<Vec<_>>()
    );
    assert!(events[0].event.prev_event_hash.is_none());
    for pair in events.windows(2) {
        assert_eq!(
            pair[1].event.prev_event_hash.as_deref(),
            Some(pair[0].event_hash.as_str())
        );
    }

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn organizations_have_independent_genesis_and_chain_heads() -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("isolation").await?;
    database.seed_organizations(&["org-a", "org-b"]).await?;
    let store = Store::connect(&database.url).await?;

    let (org_a, org_b) = tokio::join!(
        store.append_audit_event("org-a", event(1)),
        store.append_audit_event("org-b", event(2)),
    );
    let org_a = org_a?;
    let org_b = org_b?;

    assert_eq!(org_a.sequence, 1);
    assert_eq!(org_b.sequence, 1);
    assert!(org_a.event.prev_event_hash.is_none());
    assert!(org_b.event.prev_event_hash.is_none());
    assert_ne!(org_a.event_hash, org_b.event_hash);

    let heads: Vec<(String, i64, Option<String>)> = sqlx::query_as(
        r#"
        SELECT organization_id, last_sequence, last_event_hash::text
        FROM audit_chain_heads
        ORDER BY organization_id
        "#,
    )
    .fetch_all(&database.pool)
    .await?;
    assert_eq!(heads.len(), 2);
    assert_eq!(heads[0], ("org-a".into(), 1, Some(org_a.event_hash)));
    assert_eq!(heads[1], ("org-b".into(), 1, Some(org_b.event_hash)));

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn restarted_verification_rejects_deletion_mutation_and_reordering(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("tamper").await?;
    database
        .seed_organizations(&["org-deleted", "org-mutated", "org-reordered"])
        .await?;
    let store = Store::connect(&database.url).await?;

    for organization_id in ["org-deleted", "org-mutated", "org-reordered"] {
        for index in 0..3 {
            store
                .append_audit_event(organization_id, event(index))
                .await?;
        }
    }
    store.close().await;

    sqlx::query("ALTER TABLE audit_events DISABLE TRIGGER audit_events_reject_update_delete")
        .execute(&database.pool)
        .await?;
    sqlx::query("DELETE FROM audit_events WHERE organization_id = 'org-deleted' AND sequence = 3")
        .execute(&database.pool)
        .await?;
    sqlx::query(
        r#"
        UPDATE audit_events
        SET canonical_event = jsonb_set(canonical_event, '{data,tampered}', 'true'::jsonb)
        WHERE organization_id = 'org-mutated' AND sequence = 1
        "#,
    )
    .execute(&database.pool)
    .await?;
    sqlx::query(
        "UPDATE audit_events SET sequence = 99 WHERE organization_id = 'org-reordered' AND sequence = 2",
    )
    .execute(&database.pool)
    .await?;
    sqlx::query("ALTER TABLE audit_events ENABLE TRIGGER audit_events_reject_update_delete")
        .execute(&database.pool)
        .await?;

    let restarted = Store::connect(&database.url).await?;
    for organization_id in ["org-deleted", "org-mutated", "org-reordered"] {
        let error = restarted
            .load_verified_audit_chain(organization_id)
            .await
            .expect_err("tampered persistent Audit history must fail closed");
        assert!(matches!(error, StoreError::AuditChainCorrupt { .. }));
    }

    restarted.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn append_rejects_a_corrupt_locked_chain_tail() -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("corrupt_tail").await?;
    database.seed_organizations(&["org-a"]).await?;
    let store = Store::connect(&database.url).await?;
    store.append_audit_event("org-a", event(1)).await?;

    sqlx::query("ALTER TABLE audit_events DISABLE TRIGGER audit_events_reject_update_delete")
        .execute(&database.pool)
        .await?;
    sqlx::query(
        r#"
        UPDATE audit_events
        SET canonical_event = jsonb_set(canonical_event, '{data,tampered}', 'true'::jsonb)
        WHERE organization_id = 'org-a' AND sequence = 1
        "#,
    )
    .execute(&database.pool)
    .await?;
    sqlx::query("ALTER TABLE audit_events ENABLE TRIGGER audit_events_reject_update_delete")
        .execute(&database.pool)
        .await?;

    let error = store
        .append_audit_event("org-a", event(2))
        .await
        .expect_err("a corrupt chain tail must block further state changes");
    assert!(matches!(error, StoreError::AuditChainCorrupt { .. }));

    let event_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE organization_id = 'org-a'")
            .fetch_one(&database.pool)
            .await?;
    assert_eq!(event_count, 1);

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn append_boundary_rejects_invalid_event_and_unknown_organization_without_writes(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("invalid_append").await?;
    database.seed_organizations(&["org-a"]).await?;
    let store = Store::connect(&database.url).await?;

    let invalid_event = NewAuditEvent::new(
        EventType::KillSwitchTriggered,
        occurred_at(1),
        None,
        serde_json::json!("not-an-object"),
    );
    let invalid_error = store
        .append_audit_event("org-a", invalid_event)
        .await
        .expect_err("Audit data outside the schema must be rejected");
    assert!(matches!(
        invalid_error,
        StoreError::InvalidAuditEvent { .. }
    ));

    let missing_error = store
        .append_audit_event("org-missing", event(2))
        .await
        .expect_err("an event cannot create an implicit organization");
    assert!(matches!(
        missing_error,
        StoreError::OrganizationNotFound { .. }
    ));
    assert!(store.load_verified_audit_chain("org-a").await?.is_empty());

    store.close().await;
    database.destroy().await?;
    Ok(())
}

fn event(index: usize) -> NewAuditEvent {
    NewAuditEvent::new(
        EventType::KillSwitchTriggered,
        occurred_at(index),
        None,
        serde_json::json!({"index": index}),
    )
}

fn occurred_at(index: usize) -> Timestamp {
    format!("2026-08-08T00:00:{index:02}Z")
        .parse()
        .expect("test timestamp is valid RFC 3339")
}

struct TestDatabase {
    admin: PgConnection,
    pool: PgPool,
    name: String,
    url: String,
}

impl TestDatabase {
    async fn create(label: &str) -> Result<Self, Box<dyn Error>> {
        let admin_url = env::var("ATF_TEST_DATABASE_URL").expect(
            "ATF_TEST_DATABASE_URL must allow the test to create and drop PostgreSQL databases",
        );
        let admin_options = PgConnectOptions::from_str(&admin_url)?;
        let name = format!("atf_ds003_{label}_{}", unique_suffix());
        let quoted_name = quote_identifier(&name);
        let mut admin = PgConnection::connect_with(&admin_options).await?;
        admin
            .execute(format!("CREATE DATABASE {quoted_name}").as_str())
            .await?;

        let database_options = admin_options.database(&name);
        let url = database_options.to_url_lossy().to_string();
        let pool = PgPoolOptions::new()
            .max_connections(CONCURRENT_WRITERS as u32 + 4)
            .connect_with(database_options)
            .await?;
        atf_store::migrate_pool(&pool).await?;

        Ok(Self {
            admin,
            pool,
            name,
            url,
        })
    }

    async fn seed_organizations(&self, organization_ids: &[&str]) -> Result<(), sqlx::Error> {
        for organization_id in organization_ids {
            sqlx::query("INSERT INTO organizations (organization_id) VALUES ($1)")
                .bind(organization_id)
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }

    async fn destroy(self) -> Result<(), Box<dyn Error>> {
        self.pool.close().await;
        let quoted_name = quote_identifier(&self.name);
        let mut admin = self.admin;
        admin
            .execute(format!("DROP DATABASE {quoted_name}").as_str())
            .await?;
        Ok(())
    }
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
