//! DS-036 real-PostgreSQL contention proofs. Every wait is externally bounded
//! so a regression becomes a test failure instead of a hung CI worker.

use atf_store::{StoreDependencyFailure, StoreError};
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
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Barrier;

const CONTENTION_TEST_DEADLINE: Duration = Duration::from_secs(5);

#[tokio::test]
async fn real_postgres_lock_timeout_is_bounded_and_classified_fail_closed(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("lock_timeout").await?;
    database.seed_organizations(&["org-a"]).await?;
    let mut holder = PgConnection::connect(&database.url).await?;
    let contender = PgConnection::connect(&database.url).await?;
    holder.execute("BEGIN").await?;
    lock_organization(&mut holder, "org-a").await?;

    let started = Instant::now();
    let error = tokio::time::timeout(
        CONTENTION_TEST_DEADLINE,
        contend_for_organization(contender, "org-a", "200ms"),
    )
    .await
    .expect("the PostgreSQL lock timeout must finish inside the suite deadline")
    .expect_err("the held row lock must not be bypassed");
    assert!(started.elapsed() < CONTENTION_TEST_DEADLINE);
    assert_sqlstate(&error, "55P03");
    assert_eq!(
        StoreError::Database(error).dependency_failure(),
        Some(StoreDependencyFailure::Lock)
    );

    holder.execute("ROLLBACK").await?;
    assert_eq!(database.organization_count().await?, 1);
    holder.close().await?;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn real_postgres_deadlock_is_bounded_and_one_participant_fails_closed(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("deadlock").await?;
    database.seed_organizations(&["org-a", "org-b"]).await?;
    let first = PgConnection::connect(&database.url).await?;
    let second = PgConnection::connect(&database.url).await?;
    let barrier = Arc::new(Barrier::new(2));

    let (first, second) = tokio::time::timeout(CONTENTION_TEST_DEADLINE, async {
        tokio::join!(
            deadlock_participant(first, "org-a", "org-b", Arc::clone(&barrier)),
            deadlock_participant(second, "org-b", "org-a", barrier),
        )
    })
    .await
    .expect("deadlock detection must finish inside the suite deadline");

    let deadlock = match (first, second) {
        (Err(error), Ok(())) | (Ok(()), Err(error)) => error,
        outcomes => panic!("PostgreSQL must abort exactly one deadlock participant: {outcomes:?}"),
    };
    assert_sqlstate(&deadlock, "40P01");
    assert_eq!(
        StoreError::Database(deadlock).dependency_failure(),
        Some(StoreDependencyFailure::Lock)
    );
    assert_eq!(database.organization_count().await?, 2);

    database.destroy().await?;
    Ok(())
}

async fn contend_for_organization(
    mut connection: PgConnection,
    organization_id: &str,
    lock_timeout: &str,
) -> Result<(), sqlx::Error> {
    connection.execute("BEGIN").await?;
    sqlx::query("SELECT set_config('lock_timeout', $1, true)")
        .bind(lock_timeout)
        .execute(&mut connection)
        .await?;
    connection
        .execute("SET LOCAL statement_timeout = '3s'")
        .await?;
    let result = lock_organization(&mut connection, organization_id).await;
    let rollback = connection.execute("ROLLBACK").await;
    match result {
        Ok(()) => {
            rollback?;
            Ok(())
        }
        Err(error) => {
            let _ = rollback;
            Err(error)
        }
    }
}

async fn deadlock_participant(
    mut connection: PgConnection,
    first_organization: &str,
    second_organization: &str,
    barrier: Arc<Barrier>,
) -> Result<(), sqlx::Error> {
    connection.execute("BEGIN").await?;
    connection
        .execute("SET LOCAL deadlock_timeout = '100ms'")
        .await?;
    connection
        .execute("SET LOCAL statement_timeout = '3s'")
        .await?;
    lock_organization(&mut connection, first_organization).await?;
    barrier.wait().await;
    let result = lock_organization(&mut connection, second_organization).await;
    let rollback = connection.execute("ROLLBACK").await;
    match result {
        Ok(()) => {
            rollback?;
            Ok(())
        }
        Err(error) => {
            let _ = rollback;
            Err(error)
        }
    }
}

async fn lock_organization(
    connection: &mut PgConnection,
    organization_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT organization_id FROM organizations WHERE organization_id = $1 FOR UPDATE")
        .bind(organization_id)
        .execute(connection)
        .await?;
    Ok(())
}

fn assert_sqlstate(error: &sqlx::Error, expected: &str) {
    assert_eq!(
        error.as_database_error().and_then(|error| error.code()),
        Some(expected.into())
    );
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
        let name = format!("atf_ds036_{label}_{}", unique_suffix());
        let quoted_name = quote_identifier(&name);
        let mut admin = PgConnection::connect_with(&admin_options).await?;
        admin
            .execute(format!("CREATE DATABASE {quoted_name}").as_str())
            .await?;

        let database_options = admin_options.database(&name);
        let url = database_options.to_url_lossy().to_string();
        let pool = PgPoolOptions::new()
            .max_connections(4)
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

    async fn organization_count(&self) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar("SELECT count(*) FROM organizations")
            .fetch_one(&self.pool)
            .await
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
