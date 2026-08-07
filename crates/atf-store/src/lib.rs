//! The single PostgreSQL boundary for durable ATF state.
//!
//! Cross-table admission and finalization operations live here rather than in
//! the Gateway. Schema migration/compatibility, durable Audit append, and the
//! DS-004 short repository transactions and the DS-005 Gateway cutover are
//! implemented; DS-007 adds persisted lifecycle state to this boundary.

mod audit;
mod error;
mod idempotency;
mod lifecycle;
mod models;
mod repository;

use serde::{Deserialize, Serialize};
use sqlx::{migrate::Migrator, postgres::PgPoolOptions, PgPool};

pub use audit::StoredAuditEvent;
pub use error::StoreError;
pub use models::{
    AdmissionGrant, AdmissionInput, AdmittedIntent, EvaluationInput, EvaluatorLease,
    FinalizationInput, FinalizedDecision, IdempotencyReservation, IdempotencyResult,
    IdempotencyState, StoredEvaluation, StoredLifecycle,
};

static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

pub const CURRENT_SCHEMA_VERSION: i32 = 3;
const DURABLE_STATE_COMPONENT: &str = "durable_state";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaMetadata {
    pub schema_version: i32,
    pub minimum_reader_version: i32,
    pub minimum_writer_version: i32,
}

/// A verified connection pool. Construction fails closed when migrations have
/// not run or the database schema is outside this binary's supported range.
#[derive(Debug, Clone)]
pub struct Store {
    pool: PgPool,
    schema: SchemaMetadata,
}

impl Store {
    pub async fn connect(database_url: &str) -> Result<Self, StoreError> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await?;
        let schema = verify_schema(&pool).await?;
        Ok(Self { pool, schema })
    }

    pub fn schema(&self) -> SchemaMetadata {
        self.schema
    }

    pub fn is_closed(&self) -> bool {
        self.pool.is_closed()
    }

    /// Check the live PostgreSQL dependency and schema compatibility. This is
    /// intentionally read-only and is the Gateway readiness boundary.
    pub async fn check_ready(&self) -> Result<(), StoreError> {
        verify_schema(&self.pool).await?;
        Ok(())
    }

    pub async fn close(self) {
        self.pool.close().await;
    }
}

/// Apply embedded, forward-only migrations and verify the resulting schema.
pub async fn migrate(database_url: &str) -> Result<SchemaMetadata, StoreError> {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await?;
    let result = migrate_pool(&pool).await;
    pool.close().await;
    result
}

/// Apply migrations to an existing pool. This is public for operators and
/// integration tests; domain repositories remain private to this crate.
pub async fn migrate_pool(pool: &PgPool) -> Result<SchemaMetadata, StoreError> {
    MIGRATOR.run(pool).await?;
    verify_schema(pool).await
}

pub async fn verify_schema(pool: &PgPool) -> Result<SchemaMetadata, StoreError> {
    let row = sqlx::query_as::<_, (i32, i32, i32)>(
        r#"
        SELECT schema_version, minimum_reader_version, minimum_writer_version
        FROM atf_schema_metadata
        WHERE component = $1
        "#,
    )
    .bind(DURABLE_STATE_COMPONENT)
    .fetch_optional(pool)
    .await
    .map_err(|error| match error {
        sqlx::Error::Database(ref database_error)
            if database_error.code().as_deref() == Some("42P01") =>
        {
            StoreError::MissingSchemaMetadata
        }
        other => StoreError::Database(other),
    })?;

    let Some((schema_version, minimum_reader_version, minimum_writer_version)) = row else {
        return Err(StoreError::MissingSchemaMetadata);
    };

    let metadata = SchemaMetadata {
        schema_version,
        minimum_reader_version,
        minimum_writer_version,
    };

    if schema_version != CURRENT_SCHEMA_VERSION
        || minimum_reader_version > CURRENT_SCHEMA_VERSION
        || minimum_writer_version > CURRENT_SCHEMA_VERSION
    {
        return Err(StoreError::IncompatibleSchema {
            binary_version: CURRENT_SCHEMA_VERSION,
            database_version: schema_version,
            minimum_reader_version,
            minimum_writer_version,
        });
    }

    Ok(metadata)
}
