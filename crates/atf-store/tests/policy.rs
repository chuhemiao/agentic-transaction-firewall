use std::{
    env,
    error::Error,
    fs,
    path::{Path, PathBuf},
    process,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use atf_core::Timestamp;
use atf_policy::{
    policy_bundle_signature_message, PolicyBundle, PolicyBundleLoadContext, PolicyBundleSignature,
    PolicyError,
};
use atf_store::{
    operator_subject_fingerprint, OperatorKind, OperatorRegistration, OperatorRole, Store,
    StoreError,
};
use ed25519_dalek::{Signer, SigningKey};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    ConnectOptions, Connection, Executor, PgConnection, PgPool,
};

fn at(hour: u8) -> Timestamp {
    format!("2026-08-08T{hour:02}:00:00.000Z").parse().unwrap()
}

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../policies/examples")
}

fn context() -> PolicyBundleLoadContext {
    PolicyBundleLoadContext {
        organization_id: "alpha-lab".into(),
        environment: "development".into(),
        evaluated_at: at(12),
    }
}

fn second_version_dir() -> PathBuf {
    let directory = env::temp_dir().join(format!(
        "atf-policy-v2-{}-{}",
        process::id(),
        unique_suffix()
    ));
    fs::create_dir_all(&directory).unwrap();
    for entry in fs::read_dir(fixture_dir()).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            fs::copy(entry.path(), directory.join(entry.file_name())).unwrap();
        }
    }
    let manifest_path = directory.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["policy_version"] = serde_json::json!("1.1.0");
    manifest["bundle_hash"] =
        serde_json::json!("59f7a2ee2b3e0e79c2bb2cce772ef8e970c1db3f28e55f3801fa52a12bc641e7");
    fs::write(manifest_path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
    directory
}

fn proof(bundle: &PolicyBundle, key: &SigningKey) -> PolicyBundleSignature {
    let message = policy_bundle_signature_message("publisher-2026", bundle.bundle_hash()).unwrap();
    PolicyBundleSignature::from_parts(
        "publisher-2026".into(),
        bundle.bundle_hash().into(),
        key.sign(&message).to_bytes(),
    )
    .unwrap()
}

async fn provision_policy_author(store: &Store) -> Result<(), StoreError> {
    store
        .provision_operator(
            OperatorRegistration {
                operator_id: "policy-author-1".into(),
                issuer_id: "corp-idp".into(),
                subject_fingerprint: operator_subject_fingerprint(
                    "https://issuer.example.test",
                    "publisher-subject",
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
    Ok(())
}

#[tokio::test]
async fn signed_install_activation_and_rollback_are_durable_and_audited(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("lifecycle").await?;
    database.seed_organization("alpha-lab").await?;
    let store = Store::connect(&database.url).await?;
    provision_policy_author(&store).await?;

    let key = SigningKey::from_bytes(&[19; 32]);
    let first = PolicyBundle::from_dir(&fixture_dir(), &context())?;
    let second_dir = second_version_dir();
    let second = PolicyBundle::from_dir(&second_dir, &context())?;

    let installed = store
        .install_policy_bundle(
            &first,
            &proof(&first, &key),
            &key.verifying_key().to_bytes(),
            "policy-author-1",
            at(12),
        )
        .await?;
    assert_eq!(installed.policy_version, "1.0.0");
    assert_eq!(installed.publisher_key_id, "publisher-2026");

    assert!(matches!(
        store
            .install_policy_bundle(
                &first,
                &proof(&first, &key),
                &key.verifying_key().to_bytes(),
                "policy-author-1",
                at(12),
            )
            .await
            .unwrap_err(),
        StoreError::PolicyBundleConflict { .. }
    ));

    store
        .install_policy_bundle(
            &second,
            &proof(&second, &key),
            &key.verifying_key().to_bytes(),
            "policy-author-1",
            at(12),
        )
        .await?;
    let first_active = store
        .activate_policy_bundle(
            "alpha-lab",
            "development",
            "atf-example-payments",
            "1.0.0",
            "policy-author-1",
            at(13),
        )
        .await?;
    assert_eq!(first_active.lifecycle_version, 1);
    assert_eq!(first_active.bundle.policy_version(), "1.0.0");
    assert_eq!(first_active.previous_policy_version, None);

    store.close().await;
    let restarted = Store::connect(&database.url).await?;
    let restored = restarted
        .load_active_policy_bundle("alpha-lab", "development", "atf-example-payments", at(14))
        .await?;
    assert_eq!(restored.bundle.policy_version(), "1.0.0");

    let concurrent = restarted.clone();
    let (first_attempt, second_attempt) = tokio::join!(
        restarted.activate_policy_bundle(
            "alpha-lab",
            "development",
            "atf-example-payments",
            "1.1.0",
            "policy-author-1",
            at(14),
        ),
        concurrent.activate_policy_bundle(
            "alpha-lab",
            "development",
            "atf-example-payments",
            "1.1.0",
            "policy-author-1",
            at(14),
        )
    );
    let second_active = match (first_attempt, second_attempt) {
        (Ok(active), Err(error)) | (Err(error), Ok(active)) => {
            assert!(matches!(error, StoreError::PolicyBundleConflict { .. }));
            active
        }
        outcomes => panic!("exactly one concurrent activation must commit: {outcomes:?}"),
    };
    assert_eq!(second_active.lifecycle_version, 2);
    assert_eq!(
        second_active.previous_policy_version.as_deref(),
        Some("1.0.0")
    );

    let rolled_back = restarted
        .rollback_policy_bundle(
            "alpha-lab",
            "development",
            "atf-example-payments",
            "policy-author-1",
            at(15),
        )
        .await?;
    assert_eq!(rolled_back.bundle.policy_version(), "1.0.0");
    assert_eq!(
        rolled_back.previous_policy_version.as_deref(),
        Some("1.1.0")
    );
    assert_eq!(rolled_back.lifecycle_version, 3);

    let chain = restarted.load_verified_audit_chain("alpha-lab").await?;
    let policy_events = chain
        .iter()
        .filter(|event| event.event.event_type == atf_audit::EventType::PolicyChanged)
        .collect::<Vec<_>>();
    assert_eq!(policy_events.len(), 5);
    assert_eq!(
        policy_events.last().unwrap().event.data["change_kind"],
        "ROLLED_BACK"
    );
    assert_eq!(
        policy_events.last().unwrap().event.data["previous_policy_bundle_hash"],
        second.bundle_hash()
    );
    assert_eq!(
        policy_events.last().unwrap().event.data["policy_bundle_hash"],
        first.bundle_hash()
    );

    restarted.close().await;
    fs::remove_dir_all(second_dir)?;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn rejects_untrusted_unauthorized_duplicate_and_tampered_policy_state(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("fail_closed").await?;
    database.seed_organization("alpha-lab").await?;
    let store = Store::connect(&database.url).await?;
    provision_policy_author(&store).await?;
    let key = SigningKey::from_bytes(&[19; 32]);
    let bundle = PolicyBundle::from_dir(&fixture_dir(), &context())?;
    let bad_key = SigningKey::from_bytes(&[20; 32]);

    assert!(matches!(
        store
            .install_policy_bundle(
                &bundle,
                &proof(&bundle, &bad_key),
                &key.verifying_key().to_bytes(),
                "policy-author-1",
                at(12),
            )
            .await
            .unwrap_err(),
        StoreError::PolicyDomain(PolicyError::SignatureVerification)
    ));
    assert!(matches!(
        store
            .install_policy_bundle(
                &bundle,
                &proof(&bundle, &key),
                &key.verifying_key().to_bytes(),
                "db-admin-1",
                at(12),
            )
            .await
            .unwrap_err(),
        StoreError::PolicyAuthorizationDenied { .. }
    ));
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM policy_bundles")
        .fetch_one(&database.pool)
        .await?;
    assert_eq!(
        count, 0,
        "failed installs must roll Audit and state back together"
    );

    store
        .install_policy_bundle(
            &bundle,
            &proof(&bundle, &key),
            &key.verifying_key().to_bytes(),
            "policy-author-1",
            at(12),
        )
        .await?;
    store
        .activate_policy_bundle(
            "alpha-lab",
            "development",
            "atf-example-payments",
            "1.0.0",
            "policy-author-1",
            at(13),
        )
        .await?;

    database
        .pool
        .execute("ALTER TABLE policy_bundles DISABLE TRIGGER policy_bundles_protect_mutation")
        .await?;
    sqlx::query("UPDATE policy_bundles SET artifact_bytes = artifact_bytes || decode('00', 'hex')")
        .execute(&database.pool)
        .await?;
    assert!(matches!(
        store
            .load_active_policy_bundle("alpha-lab", "development", "atf-example-payments", at(14),)
            .await
            .unwrap_err(),
        StoreError::PolicyStateCorrupt { .. }
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
        let name = format!("atf_ds020_{label}_{}", unique_suffix());
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
