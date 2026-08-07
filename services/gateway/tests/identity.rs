//! DS-016 authenticated Gateway admission tests through a real PostgreSQL
//! database. The first RED case proves the pre-DS-016 unsigned path exists.

mod common;

use atf_audit::EventType;
use atf_core::Timestamp;
use atf_gateway::build_router;
use atf_identity::AgentStatus;
use axum::http::StatusCode;
use std::error::Error;
use tower::ServiceExt;

use common::{
    error_json, post_intent_request, sample_intent_json, signed_post_intent_request, test_state,
    TestDatabase, AUDIENCE, ENVIRONMENT,
};

#[tokio::test]
async fn unsigned_intent_is_rejected_and_audited_before_evaluation() -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("identity_required").await?;
    database.seed_organization("alpha-lab").await?;
    let store = database.connect().await?;
    let app = build_router(test_state(store.clone()));

    let mut request = post_intent_request("01J0000000000000000000A100", "12.50");
    request.headers_mut().remove("x-atf-identity-envelope");
    request.headers_mut().remove("x-atf-identity-signature");
    let response = app.oneshot(request).await?;

    error_json(
        response,
        StatusCode::UNAUTHORIZED,
        "IDENTITY_HEADERS_REQUIRED",
    )
    .await?;

    let chain = store.load_verified_audit_chain("alpha-lab").await?;
    assert_eq!(chain.len(), 3);
    let rejected = chain
        .last()
        .expect("rejection follows identity provisioning");
    assert_eq!(rejected.event.event_type, EventType::IdentityRejected);
    assert_eq!(
        rejected.event.data["reason_code"],
        "IDENTITY_HEADERS_REQUIRED"
    );
    assert!(rejected.event.intent_id.is_none());
    assert_eq!(database.business_record_counts().await?, (0, 0, 0, 0, 1));

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn invalid_signature_and_trusted_context_mismatches_are_audited_without_admission(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("identity_rejections").await?;
    database.seed_organization("alpha-lab").await?;
    let store = database.connect().await?;
    let app = build_router(test_state(store.clone()));

    let mut bad_signature = post_intent_request("01J0000000000000000000A200", "12.50");
    bad_signature
        .headers_mut()
        .insert("x-atf-identity-signature", "00".repeat(64).parse()?);
    error_json(
        app.clone().oneshot(bad_signature).await?,
        StatusCode::UNAUTHORIZED,
        "IDENTITY_SIGNATURE_INVALID",
    )
    .await?;

    let wrong_audience = signed_post_intent_request(
        sample_intent_json("01J0000000000000000000A300", "12.50"),
        "nonce-wrong-audience-0001",
        "another-gateway",
        ENVIRONMENT,
    );
    error_json(
        app.clone().oneshot(wrong_audience).await?,
        StatusCode::UNAUTHORIZED,
        "IDENTITY_AUDIENCE_MISMATCH",
    )
    .await?;

    let wrong_environment = signed_post_intent_request(
        sample_intent_json("01J0000000000000000000A400", "12.50"),
        "nonce-wrong-environment-1",
        AUDIENCE,
        "production",
    );
    error_json(
        app.oneshot(wrong_environment).await?,
        StatusCode::UNAUTHORIZED,
        "IDENTITY_ENVIRONMENT_MISMATCH",
    )
    .await?;

    assert_eq!(database.business_record_counts().await?, (0, 0, 0, 0, 3));
    let chain = store.load_verified_audit_chain("alpha-lab").await?;
    let rejection_codes: Vec<&str> = chain
        .iter()
        .filter(|stored| stored.event.event_type == EventType::IdentityRejected)
        .filter_map(|stored| stored.event.data["reason_code"].as_str())
        .collect();
    assert_eq!(
        rejection_codes,
        vec![
            "IDENTITY_SIGNATURE_INVALID",
            "IDENTITY_AUDIENCE_MISMATCH",
            "IDENTITY_ENVIRONMENT_MISMATCH",
        ]
    );

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn consumed_nonce_replay_is_rejected_after_restart_without_exposing_secret_material(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("nonce_restart_replay").await?;
    database.seed_organization("alpha-lab").await?;
    let first_store = database.connect().await?;
    let first_gateway = build_router(test_state(first_store.clone()));
    let nonce = "nonce-shared-after-restart-1";

    let first = signed_post_intent_request(
        sample_intent_json("01J0000000000000000000A500", "12.50"),
        nonce,
        AUDIENCE,
        ENVIRONMENT,
    );
    assert_eq!(first_gateway.oneshot(first).await?.status(), StatusCode::OK);
    first_store.close().await;

    let restarted_store = database.connect().await?;
    let restarted_gateway = build_router(test_state(restarted_store.clone()));
    let conflicting = signed_post_intent_request(
        sample_intent_json("01J0000000000000000000A600", "11.50"),
        nonce,
        AUDIENCE,
        ENVIRONMENT,
    );
    error_json(
        restarted_gateway.oneshot(conflicting).await?,
        StatusCode::CONFLICT,
        "IDENTITY_NONCE_REPLAY",
    )
    .await?;

    assert_eq!(database.business_record_counts().await?, (1, 1, 1, 1, 7));
    let chain = restarted_store
        .load_verified_audit_chain("alpha-lab")
        .await?;
    let replay = chain.last().expect("replay is the final typed evidence");
    assert_eq!(replay.event.event_type, EventType::ReplayDetected);
    assert_eq!(
        replay.event.data["nonce_hash"],
        atf_core::sha256_hex(nonce.as_bytes())
    );
    let serialized = serde_json::to_string(&replay.event)?;
    assert!(!serialized.contains(nonce));
    assert!(!serialized.contains("signature"));

    restarted_store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn identical_agent_nonce_is_isolated_by_organization_scope() -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("nonce_tenant_scope").await?;
    database.seed_organization("alpha-lab").await?;
    database.seed_organization("beta-lab").await?;
    let store = database.connect().await?;
    let app = build_router(test_state(store.clone()));
    let nonce = "nonce-shared-across-tenants-1";

    let alpha = signed_post_intent_request(
        sample_intent_json("01J0000000000000000000A700", "12.50"),
        nonce,
        AUDIENCE,
        ENVIRONMENT,
    );
    assert_eq!(app.clone().oneshot(alpha).await?.status(), StatusCode::OK);

    let mut beta_intent = sample_intent_json("01J0000000000000000000A800", "12.50");
    beta_intent["principal"]["organization_id"] = serde_json::json!("beta-lab");
    let beta = signed_post_intent_request(beta_intent, nonce, AUDIENCE, ENVIRONMENT);
    assert_eq!(app.oneshot(beta).await?.status(), StatusCode::OK);

    assert_eq!(database.business_record_counts().await?, (2, 2, 2, 2, 12));
    for organization_id in ["alpha-lab", "beta-lab"] {
        let chain = store.load_verified_audit_chain(organization_id).await?;
        assert!(chain
            .iter()
            .any(|stored| stored.event.event_type == EventType::IdentityVerified));
        assert!(!chain
            .iter()
            .any(|stored| stored.event.event_type == EventType::ReplayDetected));
    }

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn current_durable_agent_status_is_rechecked_before_policy_risk() -> Result<(), Box<dyn Error>>
{
    let database = TestDatabase::create("current_agent_status").await?;
    database.seed_organization("alpha-lab").await?;
    let store = database.connect().await?;
    let paused_at: Timestamp = Timestamp::now().to_string().parse()?;
    store
        .set_agent_status(
            "alpha-lab",
            "research-agent-01",
            AgentStatus::Paused,
            "test-operator",
            "TEST_PAUSE",
            paused_at,
        )
        .await?;
    let app = build_router(test_state(store.clone()));

    error_json(
        app.oneshot(post_intent_request("01J0000000000000000000A900", "12.50"))
            .await?,
        StatusCode::FORBIDDEN,
        "IDENTITY_AGENT_NOT_ACTIVE",
    )
    .await?;

    assert_eq!(database.business_record_counts().await?, (0, 0, 0, 0, 1));
    let chain = store.load_verified_audit_chain("alpha-lab").await?;
    assert_eq!(
        chain.last().expect("rejection is durable").event.event_type,
        EventType::IdentityRejected
    );

    store.close().await;
    database.destroy().await?;
    Ok(())
}
