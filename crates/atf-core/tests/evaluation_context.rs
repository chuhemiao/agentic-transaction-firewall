use std::str::FromStr;

use atf_core::{
    EvaluationContext, EvaluationContextError, EvaluationContextInput, EvidenceEnvelope,
    EvidenceKind, EvidenceSource, EvidenceTrustPolicy, EvidenceTrustPolicyReference,
    ExternalSnapshotReference, RepositorySnapshot, SimulationReference, Timestamp,
    TrustedEvidenceSource, VersionedArtifactReference,
};

fn timestamp(value: &str) -> Timestamp {
    Timestamp::from_str(value).unwrap()
}

fn hash(byte: char) -> String {
    byte.to_string().repeat(64)
}

fn context(agent_context: serde_json::Value) -> EvaluationContext {
    EvaluationContext::new(context_input(agent_context)).unwrap()
}

fn context_input(agent_context: serde_json::Value) -> EvaluationContextInput {
    EvaluationContextInput {
        evaluation_id: "01J0000000000000000000EC00".into(),
        intent_id: "01J00000000000000000000100".into(),
        intent_hash: hash('a'),
        evaluation_time: timestamp("2098-12-31T23:56:00Z"),
        environment: "development".into(),
        profile_id: "atf.agent-commerce.payment".into(),
        profile_version: "1.0".into(),
        policy: VersionedArtifactReference::available("atf-example-payments", "1.0.0", hash('b'))
            .unwrap(),
        risk: VersionedArtifactReference::available(
            "atf-risk-engine-v1",
            "risk-rules-1.0.0",
            hash('c'),
        )
        .unwrap(),
        context_snapshot_id: "01J0000000000000000000CS00".into(),
        agent_context,
        evidence: Vec::new(),
        evidence_trust_policy: EvidenceTrustPolicyReference::not_configured(
            "TRUST_POLICY_NOT_CONFIGURED",
        )
        .unwrap(),
        history: RepositorySnapshot::new("audit-chain:alpha-lab:2", 2, hash('d')).unwrap(),
        market_data: ExternalSnapshotReference::unavailable("MARKET_DATA_SNAPSHOT_UNAVAILABLE")
            .unwrap(),
        simulation: SimulationReference::not_run("SIMULATOR_NOT_IMPLEMENTED").unwrap(),
    }
}

#[test]
fn context_hash_is_canonical_and_persisted_round_trip_is_verified() {
    let first = context(serde_json::json!({
        "task_budget": "20.00",
        "requested_by_tool": "mcp-market-data"
    }));
    let reordered = context(serde_json::json!({
        "requested_by_tool": "mcp-market-data",
        "task_budget": "20.00"
    }));

    assert_eq!(
        first.evaluation_context_hash(),
        reordered.evaluation_context_hash()
    );
    assert_eq!(first.canonical_bytes(), reordered.canonical_bytes());
    assert_eq!(first.agent_context_hash(), reordered.agent_context_hash());
    assert!(first
        .verify_agent_context(&serde_json::json!({
            "requested_by_tool": "mcp-market-data",
            "task_budget": "20.00"
        }))
        .is_ok());
    assert!(matches!(
        first.verify_agent_context(&serde_json::json!({"task_budget": "0.01"})),
        Err(EvaluationContextError::HashMismatch)
    ));
    assert_eq!(
        first.evaluation_context_hash(),
        "876aeb8534044452734b0ef4a5023606e8b79a3ff28362929e3de8c750a5415b"
    );
    assert!(first.is_newly_constructed());

    let loaded =
        EvaluationContext::from_persisted(first.canonical_bytes(), first.evaluation_context_hash())
            .unwrap();
    assert_eq!(loaded, first);
    assert!(!loaded.is_newly_constructed());

    let mut tampered: serde_json::Value = serde_json::from_slice(first.canonical_bytes()).unwrap();
    tampered["environment"] = serde_json::json!("production");
    assert!(matches!(
        EvaluationContext::from_persisted(
            &serde_json::to_vec(&tampered).unwrap(),
            first.evaluation_context_hash(),
        ),
        Err(EvaluationContextError::HashMismatch)
    ));
}

#[test]
fn verified_evidence_is_bound_and_freshness_is_rechecked_at_snapshot_time() {
    let envelope = EvidenceEnvelope::new(
        EvidenceKind::Price,
        EvidenceSource::AtfEnriched,
        "vendor-history-v1",
        timestamp("2098-12-31T23:55:00Z"),
        timestamp("2098-12-31T23:57:00Z"),
        serde_json::json!({"amount": "12.00", "asset": "USDC"}),
        Some(9_500),
    )
    .unwrap();
    let trust = EvidenceTrustPolicy::new([TrustedEvidenceSource::unsigned(
        EvidenceSource::AtfEnriched,
        "vendor-history-v1",
        [EvidenceKind::Price],
    )
    .unwrap()])
    .unwrap();
    let verified = trust
        .verify(&envelope, timestamp("2098-12-31T23:56:00Z"))
        .unwrap();
    let trust_hash = trust.policy_hash().unwrap();
    let mut input = context_input(serde_json::json!({}));
    input.evidence = vec![verified.clone()];
    input.evidence_trust_policy =
        EvidenceTrustPolicyReference::configured("trust-policy-1", trust_hash.clone()).unwrap();

    let snapshot = EvaluationContext::new(input).unwrap();
    assert_eq!(
        snapshot.context_source_ids(),
        vec!["agent-intent-context", "vendor-history-v1"]
    );
    assert_eq!(
        snapshot
            .evidence_envelopes()
            .map(EvidenceEnvelope::evidence_hash)
            .collect::<Vec<_>>(),
        vec![envelope.evidence_hash()]
    );
    assert!(EvaluationContext::from_persisted(
        snapshot.canonical_bytes(),
        snapshot.evaluation_context_hash(),
    )
    .is_ok());

    let mut stale_input = context_input(serde_json::json!({}));
    stale_input.evaluation_time = envelope.expires_at();
    stale_input.evidence = vec![verified];
    stale_input.evidence_trust_policy =
        EvidenceTrustPolicyReference::configured("trust-policy-1", trust_hash).unwrap();
    assert!(matches!(
        EvaluationContext::new(stale_input),
        Err(EvaluationContextError::Invalid(reason))
            if reason.contains("fresh at evaluation_time")
    ));

    let verified = trust
        .verify(&envelope, timestamp("2098-12-31T23:56:00Z"))
        .unwrap();
    let mut mislabeled = context_input(serde_json::json!({}));
    mislabeled.evidence = vec![verified];
    mislabeled.evidence_trust_policy =
        EvidenceTrustPolicyReference::configured("trust-policy-1", hash('f')).unwrap();
    assert!(matches!(
        EvaluationContext::new(mislabeled),
        Err(EvaluationContextError::Invalid(reason))
            if reason.contains("does not match its verifier")
    ));
}

#[test]
fn every_selected_artifact_and_explicit_unavailable_input_is_bound() {
    let baseline = context(serde_json::json!({}));
    let value: serde_json::Value = serde_json::from_slice(baseline.canonical_bytes()).unwrap();

    for (pointer, replacement) in [
        (
            "/evaluation_time",
            serde_json::json!("2098-12-31T23:56:01Z"),
        ),
        ("/profile_version", serde_json::json!("2.0")),
        ("/policy/version", serde_json::json!("1.0.1")),
        ("/risk/hash", serde_json::json!(hash('e'))),
        ("/history/through_sequence", serde_json::json!(3)),
        (
            "/market_data/reason_code",
            serde_json::json!("DIFFERENT_REASON"),
        ),
        (
            "/simulation/reason_code",
            serde_json::json!("DIFFERENT_REASON"),
        ),
    ] {
        let mut candidate = value.clone();
        *candidate.pointer_mut(pointer).unwrap() = replacement;
        assert!(matches!(
            EvaluationContext::from_persisted(
                &serde_json::to_vec(&candidate).unwrap(),
                baseline.evaluation_context_hash(),
            ),
            Err(EvaluationContextError::HashMismatch)
        ));
    }
}

#[test]
fn public_schema_matches_the_closed_runtime_contract() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/evaluation-context.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let baseline = context(serde_json::json!({}));
    let baseline_value: serde_json::Value =
        serde_json::from_slice(baseline.canonical_bytes()).unwrap();
    assert!(validator.is_valid(&baseline_value));

    for (pointer, replacement) in [
        ("/evaluation_context_version", serde_json::json!("2")),
        ("/intent_hash", serde_json::json!("A".repeat(64))),
        ("/simulation/status", serde_json::json!("COMPLETED")),
        ("/history/through_sequence", serde_json::json!(0)),
    ] {
        let mut candidate = baseline_value.clone();
        *candidate.pointer_mut(pointer).unwrap() = replacement;
        assert!(!validator.is_valid(&candidate), "Schema accepted {pointer}");
        assert!(EvaluationContext::from_persisted(
            &serde_json::to_vec(&candidate).unwrap(),
            baseline.evaluation_context_hash(),
        )
        .is_err());
    }

    let mut unknown = baseline_value;
    unknown["unexpected"] = serde_json::json!(true);
    assert!(!validator.is_valid(&unknown));
    assert!(EvaluationContext::from_persisted(
        &serde_json::to_vec(&unknown).unwrap(),
        baseline.evaluation_context_hash(),
    )
    .is_err());
}
