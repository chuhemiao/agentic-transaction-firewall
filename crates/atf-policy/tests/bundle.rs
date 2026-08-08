use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};

use atf_core::{
    EvaluationContext, EvaluationContextInput, EvidenceTrustPolicyReference,
    ExternalSnapshotReference, RepositorySnapshot, SimulationReference, Timestamp,
    VersionedArtifactReference,
};
use atf_policy::{
    policy_bundle_signature_message, PolicyBundle, PolicyBundleArtifact, PolicyBundleLoadContext,
    PolicyBundleSignature, PolicyDecision, PolicyError,
};
use ed25519_dalek::{Signer, SigningKey};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../policies/examples")
}

fn load_context(organization_id: &str, evaluated_at: &str) -> PolicyBundleLoadContext {
    PolicyBundleLoadContext {
        organization_id: organization_id.to_owned(),
        environment: "development".to_owned(),
        evaluated_at: Timestamp::from_str(evaluated_at).unwrap(),
    }
}

fn fixture_intent() -> atf_intent::TransactionIntent {
    let raw = include_str!("../../../examples/x402-research-agent/intent.json");
    atf_intent::validate(raw).expect("the example Intent is valid")
}

fn evaluation_context(
    bundle: &PolicyBundle,
    intent: &atf_intent::TransactionIntent,
    evaluated_at: Timestamp,
) -> EvaluationContext {
    let profile = atf_intent::validate_profile(intent).unwrap();
    EvaluationContext::new(EvaluationContextInput {
        evaluation_id: "01J0000000000000000000EVAL".into(),
        intent_id: intent.intent_id.clone(),
        intent_hash: intent.canonical_hash(),
        evaluation_time: evaluated_at,
        environment: bundle.environment().into(),
        profile_id: profile.id().into(),
        profile_version: profile.version().into(),
        policy: VersionedArtifactReference::available(
            bundle.bundle_id(),
            bundle.policy_version(),
            bundle.bundle_hash(),
        )
        .unwrap(),
        risk: VersionedArtifactReference::unavailable("RISK_NOT_USED").unwrap(),
        context_snapshot_id: "01J0000000000000000000SNAP".into(),
        agent_context: intent.context.clone(),
        evidence: Vec::new(),
        evidence_trust_policy: EvidenceTrustPolicyReference::not_configured(
            "TRUST_POLICY_NOT_CONFIGURED",
        )
        .unwrap(),
        history: RepositorySnapshot::new("audit-chain:alpha-lab:1", 1, "0".repeat(64)).unwrap(),
        market_data: ExternalSnapshotReference::unavailable("MARKET_DATA_UNAVAILABLE").unwrap(),
        simulation: SimulationReference::not_run("SIMULATOR_NOT_IMPLEMENTED").unwrap(),
    })
    .unwrap()
}

fn copy_fixture() -> PathBuf {
    let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let destination = std::env::temp_dir().join(format!(
        "atf-policy-bundle-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&destination).unwrap();
    for entry in fs::read_dir(fixture_dir()).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            fs::copy(entry.path(), destination.join(entry.file_name())).unwrap();
        }
    }
    destination
}

#[test]
fn loads_a_scoped_schema_validated_bundle_with_deterministic_identity() {
    let context = load_context("alpha-lab", "2026-08-08T12:00:00Z");
    let first = PolicyBundle::from_dir(&fixture_dir(), &context).unwrap();
    let second = PolicyBundle::from_dir(&fixture_dir(), &context).unwrap();

    assert_eq!(first.bundle_id(), "atf-example-payments");
    assert_eq!(first.policy_version(), "1.0.0");
    assert_eq!(first.bundle_hash(), second.bundle_hash());
    assert_eq!(
        first.bundle_hash(),
        "87276dc9ae9b5cfd09bc664fc12a7a6d1bdc6cec3f847644239b27a368478373"
    );

    let intent = fixture_intent();
    let evaluation_context = evaluation_context(&first, &intent, context.evaluated_at);
    let outcome = first.evaluate(&intent, &evaluation_context).unwrap();
    assert_eq!(outcome.decision, PolicyDecision::Permit);
    assert_eq!(outcome.bundle_id, "atf-example-payments");
    assert_eq!(outcome.policy_version, "1.0.0");
    assert_eq!(outcome.bundle_hash, first.bundle_hash());
}

#[test]
fn rejects_policy_bytes_that_do_not_match_the_manifest_digest() {
    let directory = copy_fixture();
    fs::write(
        directory.join("payment-budget.cedar"),
        "permit (principal, action, resource);\n",
    )
    .unwrap();

    let error = PolicyBundle::from_dir(
        &directory,
        &load_context("alpha-lab", "2026-08-08T12:00:00Z"),
    )
    .expect_err("tampered Policy bytes must fail closed");
    assert!(matches!(error, PolicyError::FileDigestMismatch { .. }));

    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn rejects_wrong_organization_and_inactive_or_expired_versions() {
    let directory = fixture_dir();

    let wrong_scope = PolicyBundle::from_dir(
        &directory,
        &load_context("other-organization", "2026-08-08T12:00:00Z"),
    )
    .expect_err("organization scope is authoritative");
    assert!(matches!(wrong_scope, PolicyError::ScopeMismatch { .. }));

    for evaluated_at in ["2025-12-31T23:59:59Z", "2100-01-01T00:00:00Z"] {
        let error = PolicyBundle::from_dir(&directory, &load_context("alpha-lab", evaluated_at))
            .expect_err("inactive and expired bundles must fail closed");
        assert!(matches!(error, PolicyError::Inactive { .. }));
    }
}

#[test]
fn rejects_sub_millisecond_manifest_times_before_hashing() {
    let directory = copy_fixture();
    let manifest_path = directory.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["activates_at"] = serde_json::json!("2026-01-01T00:00:00.000001Z");
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let error = PolicyBundle::from_dir(
        &directory,
        &load_context("alpha-lab", "2026-08-08T12:00:00Z"),
    )
    .expect_err("canonical timestamps must not discard precision");
    assert!(matches!(error, PolicyError::Manifest(_)));

    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn rejects_a_manifest_hash_mismatch_and_unlisted_policy_files() {
    let directory = copy_fixture();
    let manifest_path = directory.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["bundle_hash"] = serde_json::json!("f".repeat(64));
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    let error = PolicyBundle::from_dir(
        &directory,
        &load_context("alpha-lab", "2026-08-08T12:00:00Z"),
    )
    .expect_err("the declared Bundle hash is authoritative");
    assert!(matches!(error, PolicyError::BundleHashMismatch { .. }));

    fs::copy(
        directory.join("payment-budget.cedar"),
        directory.join("undeclared.cedar"),
    )
    .unwrap();
    manifest["bundle_hash"] =
        serde_json::json!("87276dc9ae9b5cfd09bc664fc12a7a6d1bdc6cec3f847644239b27a368478373");
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    let error = PolicyBundle::from_dir(
        &directory,
        &load_context("alpha-lab", "2026-08-08T12:00:00Z"),
    )
    .expect_err("all Cedar files must be bound by the manifest");
    assert!(matches!(error, PolicyError::UnlistedPolicyFile(_)));

    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn cedar_schema_validation_rejects_invalid_policies_and_requests() {
    let invalid_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/schema-invalid");
    let error = PolicyBundle::from_dir(
        &invalid_dir,
        &load_context("alpha-lab", "2026-08-08T12:00:00Z"),
    )
    .expect_err("a schema-invalid policy must never become evaluable");
    assert!(matches!(error, PolicyError::CedarValidation(_)));

    let context = load_context("alpha-lab", "2026-08-08T12:00:00Z");
    let bundle = PolicyBundle::from_dir(&fixture_dir(), &context).unwrap();
    let valid = fixture_intent();
    let bound_context = evaluation_context(&bundle, &valid, context.evaluated_at);
    let mut unsupported = valid;
    unsupported.action.operation = "unsupported_action".into();
    let error = bundle
        .evaluate(&unsupported, &bound_context)
        .expect_err("an Intent outside the persisted Context must fail closed");
    assert!(matches!(error, PolicyError::EvaluationContext(_)));

    let intent = fixture_intent();
    let expired_context = evaluation_context(
        &bundle,
        &intent,
        Timestamp::from_str("2100-01-01T00:00:00Z").unwrap(),
    );
    let error = bundle
        .evaluate(&intent, &expired_context)
        .expect_err("expiry is rechecked for every evaluation");
    assert!(matches!(error, PolicyError::Inactive { .. }));
}

#[test]
fn rejects_nested_paths_and_oversized_bundle_inputs_before_reading_them() {
    let directory = copy_fixture();
    let manifest_path = directory.join("manifest.json");
    let original = fs::read_to_string(&manifest_path).unwrap();
    let mut manifest: serde_json::Value = serde_json::from_str(&original).unwrap();
    manifest["policy_files"][0]["path"] = serde_json::json!("nested/payment-budget.cedar");
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    let error = PolicyBundle::from_dir(
        &directory,
        &load_context("alpha-lab", "2026-08-08T12:00:00Z"),
    )
    .expect_err("v1 Bundle files must stay directly under the Bundle root");
    assert!(matches!(
        error,
        PolicyError::ManifestSchema(_) | PolicyError::InvalidFilePath(_)
    ));

    let mut oversized_manifest = original.into_bytes();
    oversized_manifest.extend(std::iter::repeat_n(b' ', 70 * 1024));
    fs::write(&manifest_path, oversized_manifest).unwrap();
    let error = PolicyBundle::from_dir(
        &directory,
        &load_context("alpha-lab", "2026-08-08T12:00:00Z"),
    )
    .expect_err("oversized manifests must fail before allocation grows unchecked");
    assert!(matches!(error, PolicyError::FileTooLarge { .. }));

    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn archive_round_trip_revalidates_every_bound_byte() {
    let context = load_context("alpha-lab", "2026-08-08T12:00:00Z");
    let loaded = PolicyBundle::from_dir(&fixture_dir(), &context).unwrap();
    let encoded = loaded.artifact().encode();
    let artifact = PolicyBundleArtifact::decode(&encoded).unwrap();
    let restored = PolicyBundle::from_artifact(artifact, &context).unwrap();

    assert_eq!(restored.bundle_hash(), loaded.bundle_hash());
    assert_eq!(restored.organization_id(), "alpha-lab");
    assert_eq!(restored.environment(), "development");
    assert_eq!(restored.artifact().encode(), encoded);

    let mut tampered = encoded;
    let last = tampered.last_mut().expect("archive is not empty");
    *last ^= 1;
    let artifact = PolicyBundleArtifact::decode(&tampered).unwrap();
    let error = PolicyBundle::from_artifact(artifact, &context)
        .expect_err("archived Policy bytes must be revalidated after durable load");
    assert!(matches!(error, PolicyError::FileDigestMismatch { .. }));
}

#[test]
fn detached_signature_binds_key_id_and_exact_bundle_hash() {
    let context = load_context("alpha-lab", "2026-08-08T12:00:00Z");
    let bundle = PolicyBundle::from_dir(&fixture_dir(), &context).unwrap();
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let message = policy_bundle_signature_message("publisher-2026", bundle.bundle_hash()).unwrap();
    let signature = signing_key.sign(&message).to_bytes();
    let proof = PolicyBundleSignature::from_parts(
        "publisher-2026".into(),
        bundle.bundle_hash().into(),
        signature,
    )
    .unwrap();

    proof
        .verify(&bundle, &signing_key.verifying_key().to_bytes())
        .unwrap();
    assert_eq!(proof.key_id(), "publisher-2026");
    assert_eq!(proof.bundle_hash(), bundle.bundle_hash());

    let wrong_key = SigningKey::from_bytes(&[8; 32]);
    assert!(matches!(
        proof.verify(&bundle, &wrong_key.verifying_key().to_bytes()),
        Err(PolicyError::SignatureVerification)
    ));

    let wrong_key_id = PolicyBundleSignature::from_parts(
        "other-publisher".into(),
        bundle.bundle_hash().into(),
        signature,
    )
    .unwrap();
    assert!(matches!(
        wrong_key_id.verify(&bundle, &signing_key.verifying_key().to_bytes()),
        Err(PolicyError::SignatureVerification)
    ));

    let document = serde_json::json!({
        "signature_version": "1",
        "algorithm": "Ed25519",
        "key_id": proof.key_id(),
        "bundle_hash": proof.bundle_hash(),
        "signature": signature.iter().map(|byte| format!("{byte:02x}")).collect::<String>()
    });
    PolicyBundleSignature::from_json(&serde_json::to_string(&document).unwrap()).unwrap();
    let mut unknown = document;
    unknown["untrusted_hint"] = serde_json::json!("ignore-signature");
    assert!(matches!(
        PolicyBundleSignature::from_json(&serde_json::to_string(&unknown).unwrap()),
        Err(PolicyError::SignatureProof(_))
    ));
}
