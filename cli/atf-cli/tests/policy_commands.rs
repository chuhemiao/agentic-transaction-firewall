use std::{
    env,
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::{self, Command, Output},
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use atf_policy::{policy_bundle_signature_message, PolicyBundle, PolicyBundleLoadContext};
use atf_store::{
    operator_subject_fingerprint, OperatorKind, OperatorRegistration, OperatorRole, Store,
};
use ed25519_dalek::{Signer, SigningKey};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    ConnectOptions, Connection, Executor, PgConnection, PgPool,
};

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../policies/examples")
}

fn at(hour: u8) -> atf_core::Timestamp {
    format!("2026-08-08T{hour:02}:00:00.000Z").parse().unwrap()
}

#[tokio::test]
async fn real_cli_installs_activates_and_rolls_back_signed_policy() -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create().await?;
    database.seed_organization("alpha-lab").await?;
    let store = Store::connect(&database.url).await?;
    store
        .provision_operator(
            OperatorRegistration {
                operator_id: "policy-author-1".into(),
                issuer_id: "corp-idp".into(),
                subject_fingerprint: operator_subject_fingerprint(
                    "https://issuer.example.test",
                    "policy-author-subject",
                )?,
                principal_kind: OperatorKind::Human,
                audit_organization_id: "alpha-lab".into(),
                created_at: at(8),
            },
            "db-admin-1",
            at(9),
        )
        .await?;
    store
        .grant_operator_role(
            "policy-author-1",
            "alpha-lab",
            OperatorRole::PolicyAuthor,
            "db-admin-1",
            "INITIAL_POLICY_AUTHORITY",
            at(10),
        )
        .await?;
    store.close().await;

    let signing_key = SigningKey::from_bytes(&[21; 32]);
    let key_path = env::temp_dir().join(format!("atf-policy-public-{}.hex", unique_suffix()));
    fs::write(
        &key_path,
        format!("{}\n", hex::encode(signing_key.verifying_key().to_bytes())),
    )?;
    let first_dir = signed_bundle_dir("1.0.0", None, &signing_key)?;
    let second_dir = signed_bundle_dir(
        "1.1.0",
        Some("59f7a2ee2b3e0e79c2bb2cce772ef8e970c1db3f28e55f3801fa52a12bc641e7"),
        &signing_key,
    )?;

    for directory in [&first_dir, &second_dir] {
        let install = run_atf(
            &database.url,
            &[
                "policy",
                "install",
                directory.to_str().unwrap(),
                "--organization-id",
                "alpha-lab",
                "--environment",
                "development",
                "--publisher-public-key",
                key_path.to_str().unwrap(),
                "--actor-id",
                "policy-author-1",
                "--occurred-at",
                "2026-08-08T12:00:00.000Z",
            ],
        );
        assert_success(&install);
        assert!(String::from_utf8_lossy(&install.stdout).contains("publisher-2026"));
    }

    for (version, expected_lifecycle) in [("1.0.0", 1), ("1.1.0", 2)] {
        let activate = run_atf(
            &database.url,
            &[
                "policy",
                "activate",
                "--organization-id",
                "alpha-lab",
                "--environment",
                "development",
                "--bundle-id",
                "atf-example-payments",
                "--policy-version",
                version,
                "--actor-id",
                "policy-author-1",
                "--occurred-at",
                if expected_lifecycle == 1 {
                    "2026-08-08T13:00:00.000Z"
                } else {
                    "2026-08-08T14:00:00.000Z"
                },
            ],
        );
        assert_success(&activate);
        assert_policy_output(&activate, version, expected_lifecycle);
    }

    let rollback = run_atf(
        &database.url,
        &[
            "policy",
            "rollback",
            "--organization-id",
            "alpha-lab",
            "--environment",
            "development",
            "--bundle-id",
            "atf-example-payments",
            "--actor-id",
            "policy-author-1",
            "--occurred-at",
            "2026-08-08T15:00:00.000Z",
        ],
    );
    assert_success(&rollback);
    assert_policy_output(&rollback, "1.0.0", 3);

    let store = Store::connect(&database.url).await?;
    assert_eq!(
        store
            .load_active_policy_bundle("alpha-lab", "development", "atf-example-payments", at(16),)
            .await?
            .bundle
            .policy_version(),
        "1.0.0"
    );
    store.close().await;

    fs::remove_file(key_path)?;
    fs::remove_dir_all(first_dir)?;
    fs::remove_dir_all(second_dir)?;
    database.destroy().await?;
    Ok(())
}

fn signed_bundle_dir(
    version: &str,
    replacement_hash: Option<&str>,
    key: &SigningKey,
) -> Result<PathBuf, Box<dyn Error>> {
    let directory = env::temp_dir().join(format!("atf-cli-policy-{}", unique_suffix()));
    fs::create_dir_all(&directory)?;
    for entry in fs::read_dir(fixture_dir())? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            fs::copy(entry.path(), directory.join(entry.file_name()))?;
        }
    }
    let manifest_path = directory.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path)?)?;
    manifest["policy_version"] = serde_json::json!(version);
    if let Some(bundle_hash) = replacement_hash {
        manifest["bundle_hash"] = serde_json::json!(bundle_hash);
    }
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;
    let bundle_hash = manifest["bundle_hash"].as_str().unwrap();
    let message = policy_bundle_signature_message("publisher-2026", bundle_hash)?;
    let signature = key.sign(&message).to_bytes();
    fs::write(
        directory.join("signature.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "signature_version": "1",
            "algorithm": "Ed25519",
            "key_id": "publisher-2026",
            "bundle_hash": bundle_hash,
            "signature": hex::encode(signature)
        }))?,
    )?;
    let loaded = PolicyBundle::from_dir(
        &directory,
        &PolicyBundleLoadContext {
            organization_id: "alpha-lab".into(),
            environment: "development".into(),
            evaluated_at: at(12),
        },
    )?;
    assert_eq!(loaded.policy_version(), version);
    Ok(directory)
}

fn run_atf(database_url: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_atf"))
        .env("DATABASE_URL", database_url)
        .args(args)
        .output()
        .expect("real atf binary must start")
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_policy_output(output: &Output, version: &str, lifecycle_version: i64) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(&format!("policy_version: {version}")));
    assert!(stdout.contains(&format!("lifecycle_version: {lifecycle_version}")));
    assert!(stdout.contains("audit_event_id:"));
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
        let name = format!("atf_ds020_cli_{}", unique_suffix());
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
