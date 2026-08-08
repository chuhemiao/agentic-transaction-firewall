use std::{
    env,
    error::Error,
    fs,
    io::Write,
    path::PathBuf,
    process::{self, Command, Output, Stdio},
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use atf_identity::{AgentRecord, AgentStatus};
use atf_store::{OperatorStatus, Store};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    ConnectOptions, Connection, Executor, PgConnection, PgPool,
};

const PUBLIC_KEY_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

#[tokio::test]
async fn real_cli_provisions_pauses_and_revokes_durable_identity() -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create().await?;
    database.seed_organization("alpha-lab").await?;
    let record_path = agent_record_path();
    fs::write(&record_path, serde_json::to_vec_pretty(&agent_record())?)?;

    let provision = run_atf(
        &database.url,
        &[
            "identity",
            "provision-agent",
            record_path.to_str().unwrap(),
            "--actor-id",
            "operator-1",
            "--occurred-at",
            "2026-08-08T10:00:00.000Z",
        ],
    );
    assert_success(&provision);
    assert_output_contract(&provision, "research-agent-01", 1);

    let register = run_atf(
        &database.url,
        &[
            "identity",
            "register-key",
            "--organization-id",
            "alpha-lab",
            "--agent-id",
            "research-agent-01",
            "--key-id",
            "identity-key-2026-01",
            "--public-key-hex",
            PUBLIC_KEY_HEX,
            "--activates-at",
            "2026-08-08T10:00:00.000Z",
            "--expires-at",
            "2026-09-08T10:00:00.000Z",
            "--actor-id",
            "operator-1",
            "--occurred-at",
            "2026-08-08T10:00:00.000Z",
        ],
    );
    assert_success(&register);
    assert_output_contract(&register, "identity-key-2026-01", 1);

    let pause = run_atf(
        &database.url,
        &[
            "identity",
            "set-agent-status",
            "--organization-id",
            "alpha-lab",
            "--agent-id",
            "research-agent-01",
            "--status",
            "PAUSED",
            "--actor-id",
            "operator-1",
            "--reason-code",
            "OPERATOR_PAUSE",
            "--occurred-at",
            "2026-08-08T11:00:00.000Z",
        ],
    );
    assert_success(&pause);
    assert_output_contract(&pause, "research-agent-01", 2);

    let revoke = run_atf(
        &database.url,
        &[
            "identity",
            "revoke-key",
            "--organization-id",
            "alpha-lab",
            "--agent-id",
            "research-agent-01",
            "--key-id",
            "identity-key-2026-01",
            "--actor-id",
            "operator-1",
            "--reason-code",
            "KEY_COMPROMISED",
            "--occurred-at",
            "2026-08-08T11:00:00.000Z",
        ],
    );
    assert_success(&revoke);
    assert_output_contract(&revoke, "identity-key-2026-01", 2);

    let store = Store::connect(&database.url).await?;
    let snapshot = store
        .load_identity_snapshot("alpha-lab", "research-agent-01", "identity-key-2026-01")
        .await?;
    assert_eq!(snapshot.agent().record.status, AgentStatus::Paused);
    assert_eq!(
        snapshot.key().record.revoked_at,
        Some("2026-08-08T11:00:00.000Z".parse().unwrap())
    );
    assert_eq!(store.load_verified_audit_chain("alpha-lab").await?.len(), 4);
    store.close().await;

    let private_key_attempt = run_atf(
        &database.url,
        &[
            "identity",
            "register-key",
            "--organization-id",
            "alpha-lab",
            "--agent-id",
            "research-agent-01",
            "--key-id",
            "forbidden-private-key",
            "--private-key-hex",
            "00",
        ],
    );
    assert!(!private_key_attempt.status.success());
    assert!(
        String::from_utf8_lossy(&private_key_attempt.stderr).contains("--private-key-hex"),
        "private-key input must remain outside the CLI contract"
    );

    fs::remove_file(record_path)?;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn real_cli_provisions_and_revokes_operator_access_without_persisting_subject(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create().await?;
    database.seed_organization("alpha-lab").await?;
    let raw_subject = "external-subject-must-remain-private";
    let provision = run_atf_with_stdin(
        &database.url,
        &[
            "operator",
            "provision-subject",
            "--organization-id",
            "alpha-lab",
            "--operator-id",
            "operator-1",
            "--issuer-id",
            "corp-idp",
            "--issuer-url",
            "https://issuer.example.test",
            "--principal-kind",
            "HUMAN",
            "--created-at",
            "2026-08-08T09:00:00.000Z",
            "--actor-id",
            "db-admin-1",
            "--occurred-at",
            "2026-08-08T10:00:00.000Z",
        ],
        raw_subject,
    );
    assert_success(&provision);
    assert_output_contract(&provision, "operator-1", 1);
    assert!(!String::from_utf8_lossy(&provision.stdout).contains(raw_subject));

    for (action, reason, occurred_at, version) in [
        (
            "grant-role",
            "INITIAL_ACCESS",
            "2026-08-08T11:00:00.000Z",
            1,
        ),
        (
            "revoke-role",
            "ACCESS_REMOVED",
            "2026-08-08T12:00:00.000Z",
            2,
        ),
    ] {
        let output = run_atf(
            &database.url,
            &[
                "operator",
                action,
                "--organization-id",
                "alpha-lab",
                "--operator-id",
                "operator-1",
                "--role",
                "auditor",
                "--actor-id",
                "db-admin-1",
                "--reason-code",
                reason,
                "--occurred-at",
                occurred_at,
            ],
        );
        assert_success(&output);
        assert_output_contract(&output, "operator-1", version);
    }

    let disable = run_atf(
        &database.url,
        &[
            "operator",
            "set-status",
            "--operator-id",
            "operator-1",
            "--status",
            "DISABLED",
            "--actor-id",
            "db-admin-1",
            "--reason-code",
            "INCIDENT_RESPONSE",
            "--occurred-at",
            "2026-08-08T13:00:00.000Z",
        ],
    );
    assert_success(&disable);
    assert_output_contract(&disable, "operator-1", 2);

    let store = Store::connect(&database.url).await?;
    assert_eq!(
        store.load_operator("operator-1").await?.status,
        OperatorStatus::Disabled
    );
    assert_eq!(store.load_verified_audit_chain("alpha-lab").await?.len(), 4);
    store.close().await;
    let subject_persisted: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM operator_subjects
            WHERE canonical_record::text LIKE '%' || $1 || '%'
        ) OR EXISTS (
            SELECT 1 FROM audit_events
            WHERE canonical_event::text LIKE '%' || $1 || '%'
        )
        "#,
    )
    .bind(raw_subject)
    .fetch_one(&database.pool)
    .await?;
    assert!(!subject_persisted);

    database.destroy().await?;
    Ok(())
}

fn run_atf(database_url: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_atf"))
        .env("DATABASE_URL", database_url)
        .args(args)
        .output()
        .expect("real atf binary must start")
}

fn run_atf_with_stdin(database_url: &str, args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_atf"))
        .env("DATABASE_URL", database_url)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("real atf binary must start");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(stdin.as_bytes())
        .expect("subject can be written to stdin");
    child.wait_with_output().expect("atf CLI must exit")
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_output_contract(output: &Output, identifier: &str, version: i64) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(identifier), "unexpected stdout: {stdout}");
    assert!(
        stdout.contains(&format!("lifecycle_version: {version}")),
        "unexpected stdout: {stdout}"
    );
    assert!(
        stdout.contains("audit_event_id:"),
        "unexpected stdout: {stdout}"
    );
}

fn agent_record() -> AgentRecord {
    AgentRecord {
        agent_id: "research-agent-01".into(),
        organization_id: "alpha-lab".into(),
        owner_user_id: "user-001".into(),
        agent_type: "research".into(),
        model_provider: "test".into(),
        model_name: "deterministic-model".into(),
        agent_version: "1.0.0".into(),
        code_hash: "a".repeat(64),
        deployment_environment: "production".into(),
        allowed_tools: vec!["mcp-market-data".into()],
        allowed_adapters: vec!["x402".into()],
        default_budget: Some("20.00".parse().unwrap()),
        risk_tier: "standard".into(),
        status: AgentStatus::Active,
        created_at: "2026-08-08T09:00:00.000Z".parse().unwrap(),
        expires_at: Some("2027-08-08T09:00:00.000Z".parse().unwrap()),
    }
}

fn agent_record_path() -> PathBuf {
    env::temp_dir().join(format!("atf-agent-record-{}.json", unique_suffix()))
}

struct TestDatabase {
    admin: PgConnection,
    pool: PgPool,
    name: String,
    url: String,
}

impl TestDatabase {
    async fn create() -> Result<Self, Box<dyn Error>> {
        let admin_url = env::var("ATF_TEST_DATABASE_URL").expect(
            "ATF_TEST_DATABASE_URL must allow the test to create and drop PostgreSQL databases",
        );
        let admin_options = PgConnectOptions::from_str(&admin_url)?;
        let name = format!("atf_ds015_cli_{}", unique_suffix());
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
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after Unix epoch")
        .as_nanos();
    format!(
        "{}_{nanos}_{}",
        process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
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
