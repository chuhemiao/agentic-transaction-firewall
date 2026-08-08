use atf_core::Timestamp;
use atf_store::{
    operator_subject_fingerprint, OperatorKind, OperatorRegistration, OperatorRole, OperatorStatus,
    Store,
};
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

const ISSUER: &str = "https://issuer.example.test";
const SUBJECT: &str = "external-subject-must-not-be-stored";

fn at(hour: u8) -> Timestamp {
    format!("2026-08-08T{hour:02}:00:00.000Z").parse().unwrap()
}

fn registration() -> OperatorRegistration {
    OperatorRegistration {
        operator_id: "operator-1".into(),
        issuer_id: "corp-idp".into(),
        subject_fingerprint: operator_subject_fingerprint(ISSUER, SUBJECT).unwrap(),
        principal_kind: OperatorKind::Human,
        audit_organization_id: "alpha-lab".into(),
        created_at: at(9),
    }
}

#[tokio::test]
async fn operator_and_role_lifecycle_survive_restart_and_revoke_immediately(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("lifecycle").await?;
    database.seed_organization("alpha-lab").await?;
    database.seed_organization("beta-lab").await?;
    let store = Store::connect(&database.url).await?;

    let operator = store
        .provision_operator(registration(), "db-admin-1", at(10))
        .await?;
    assert_eq!(operator.status, OperatorStatus::Active);
    assert_eq!(operator.lifecycle_version, 1);
    let binding = store
        .grant_operator_role(
            "operator-1",
            "alpha-lab",
            OperatorRole::Auditor,
            "db-admin-1",
            "INITIAL_ACCESS",
            at(11),
        )
        .await?;
    assert_eq!(binding.lifecycle_version, 1);

    let fingerprint = operator_subject_fingerprint(ISSUER, SUBJECT)?;
    let principal = store
        .resolve_operator_principal("corp-idp", &fingerprint, "alpha-lab")
        .await?
        .expect("active subject is authenticated");
    assert_eq!(principal.operator_id, "operator-1");
    assert_eq!(principal.roles, vec![OperatorRole::Auditor]);
    assert_eq!(
        store
            .resolve_operator_principal("corp-idp", &fingerprint, "beta-lab")
            .await?
            .expect("subject authentication is independent of role")
            .roles,
        Vec::<OperatorRole>::new()
    );
    store.close().await;

    let restarted = Store::connect(&database.url).await?;
    assert_eq!(
        restarted
            .resolve_operator_principal("corp-idp", &fingerprint, "alpha-lab")
            .await?
            .unwrap()
            .roles,
        vec![OperatorRole::Auditor]
    );
    restarted
        .revoke_operator_role(
            "operator-1",
            "alpha-lab",
            OperatorRole::Auditor,
            "db-admin-1",
            "ACCESS_REMOVED",
            at(12),
        )
        .await?;
    assert!(restarted
        .resolve_operator_principal("corp-idp", &fingerprint, "alpha-lab")
        .await?
        .unwrap()
        .roles
        .is_empty());

    restarted
        .set_operator_status(
            "operator-1",
            OperatorStatus::Disabled,
            "db-admin-1",
            "INCIDENT_RESPONSE",
            at(13),
        )
        .await?;
    assert!(restarted
        .resolve_operator_principal("corp-idp", &fingerprint, "alpha-lab")
        .await?
        .is_none());

    let serialized_chain = restarted
        .load_verified_audit_chain("alpha-lab")
        .await?
        .iter()
        .map(|stored| serde_json::to_string(&stored.event))
        .collect::<Result<Vec<_>, _>>()?
        .join("\n");
    assert!(!serialized_chain.contains(SUBJECT));
    assert!(!serialized_chain.contains("bearer"));

    restarted.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn database_guards_and_verified_reads_reject_operator_rebinding_and_role_tampering(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("guards").await?;
    database.seed_organization("alpha-lab").await?;
    let store = Store::connect(&database.url).await?;
    store
        .provision_operator(registration(), "db-admin-1", at(10))
        .await?;
    store
        .grant_operator_role(
            "operator-1",
            "alpha-lab",
            OperatorRole::Auditor,
            "db-admin-1",
            "INITIAL_ACCESS",
            at(11),
        )
        .await?;

    for statement in [
        "UPDATE operator_subjects SET issuer_id = 'attacker' WHERE operator_id = 'operator-1'",
        "UPDATE operator_subjects SET status = 'DISABLED' WHERE operator_id = 'operator-1'",
        "UPDATE operator_roles SET role = 'org_admin' WHERE operator_id = 'operator-1'",
        "DELETE FROM operator_roles WHERE operator_id = 'operator-1'",
        "DELETE FROM operator_subjects WHERE operator_id = 'operator-1'",
    ] {
        let error = database
            .pool
            .execute(statement)
            .await
            .expect_err("Operator RBAC guards must reject direct mutation");
        assert_sqlstate(&error, "55000");
    }
    for statement in [
        "TRUNCATE operator_roles",
        "TRUNCATE operator_subjects CASCADE",
    ] {
        let error = database
            .pool
            .execute(statement)
            .await
            .expect_err("Operator RBAC guards must reject truncate");
        let code = error
            .as_database_error()
            .and_then(|database_error| database_error.code())
            .map(|code| code.into_owned());
        assert!(matches!(code.as_deref(), Some("55000" | "0A000")));
    }

    store
        .revoke_operator_role(
            "operator-1",
            "alpha-lab",
            OperatorRole::Auditor,
            "db-admin-1",
            "ACCESS_REMOVED",
            at(12),
        )
        .await?;
    database
        .pool
        .execute("ALTER TABLE operator_roles DISABLE TRIGGER USER")
        .await?;
    database
        .pool
        .execute("UPDATE operator_roles SET status = 'ACTIVE' WHERE operator_id = 'operator-1'")
        .await?;
    database
        .pool
        .execute("ALTER TABLE operator_roles ENABLE TRIGGER USER")
        .await?;
    let fingerprint = operator_subject_fingerprint(ISSUER, SUBJECT)?;
    assert!(matches!(
        store
            .resolve_operator_principal("corp-idp", &fingerprint, "alpha-lab")
            .await
            .unwrap_err(),
        atf_store::StoreError::OperatorStateCorrupt { .. }
    ));

    store.close().await;
    database.destroy().await?;
    Ok(())
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
        let name = format!("atf_ds018_{label}_{}", unique_suffix());
        let quoted_name = quote_identifier(&name);
        let mut admin = PgConnection::connect_with(&admin_options).await?;
        admin
            .execute(format!("CREATE DATABASE {quoted_name}").as_str())
            .await?;

        let database_options = admin_options.database(&name);
        let url = database_options.to_url_lossy().to_string();
        let pool = PgPoolOptions::new()
            .max_connections(8)
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

    async fn seed_organization(&self, organization_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO organizations (organization_id) VALUES ($1)")
            .bind(organization_id)
            .execute(&self.pool)
            .await?;
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
    assert!(identifier
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '_'));
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
