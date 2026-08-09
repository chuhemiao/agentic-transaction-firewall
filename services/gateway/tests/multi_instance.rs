//! Reusable DS-036 proofs that independent Gateway states converge through
//! PostgreSQL rather than process-local coordination.

mod support;

use atf_audit::EventType;
use atf_gateway::build_router;
use axum::http::StatusCode;
use std::{error::Error, sync::Arc};
use tokio::sync::Barrier;
use tower::ServiceExt;

use support::{
    body_json, error_json, get_decision_request, post_intent_request, sample_intent_json,
    signed_post_intent_request, test_state, TestDatabase, AUDIENCE, ENVIRONMENT,
};

#[tokio::test]
async fn two_gateway_instances_converge_on_one_restart_safe_decision_and_audit_chain(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("multi_instance_decision").await?;
    database.seed_organization("alpha-lab").await?;
    let first_store = database.connect().await?;
    let second_store = database.connect().await?;
    let first_gateway = build_router(test_state(first_store.clone()));
    let second_gateway = build_router(test_state(second_store.clone()));
    let intent_id = "01J0000000000000000000M100";
    let barrier = Arc::new(Barrier::new(3));

    let first = {
        let barrier = Arc::clone(&barrier);
        tokio::spawn(async move {
            barrier.wait().await;
            first_gateway
                .oneshot(post_intent_request(intent_id, "12.50"))
                .await
        })
    };
    let second = {
        let barrier = Arc::clone(&barrier);
        tokio::spawn(async move {
            barrier.wait().await;
            second_gateway
                .oneshot(post_intent_request(intent_id, "12.50"))
                .await
        })
    };
    barrier.wait().await;

    let (first, second) = tokio::join!(first, second);
    let mut observed_decisions = Vec::new();
    for response in [first??, second??] {
        if response.status() == StatusCode::OK {
            observed_decisions.push(body_json(response).await?);
        } else {
            error_json(response, StatusCode::CONFLICT, "IDEMPOTENCY_IN_PROGRESS").await?;
        }
    }
    assert!(
        !observed_decisions.is_empty(),
        "at least one Gateway must return the committed result"
    );

    first_store.close().await;
    second_store.close().await;
    let restarted_store = database.connect().await?;
    let restarted_gateway = build_router(test_state(restarted_store.clone()));
    let response = restarted_gateway
        .oneshot(get_decision_request(intent_id, "alpha-lab"))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let durable = body_json(response).await?;
    for observed in observed_decisions {
        assert_eq!(observed, durable);
    }

    let finalized = restarted_store
        .load_finalized_decision("alpha-lab", intent_id)
        .await?
        .expect("the one committed Decision survives every Gateway instance");
    assert_eq!(serde_json::to_value(finalized.decision)?, durable);
    let chain = restarted_store
        .load_verified_audit_chain("alpha-lab")
        .await?;
    assert_eq!(
        chain
            .iter()
            .filter(|stored| stored.event.intent_id.as_deref() == Some(intent_id))
            .count(),
        7
    );
    assert_eq!(
        chain
            .iter()
            .filter(|stored| {
                stored.event.intent_id.as_deref() == Some(intent_id)
                    && stored.event.event_type == EventType::DecisionRecorded
            })
            .count(),
        1
    );
    assert_eq!(database.business_record_counts().await?, (1, 1, 1, 1, 1, 7));

    restarted_store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn two_gateway_instances_bind_a_conflicting_nonce_once_and_audit_the_loser(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("multi_instance_nonce").await?;
    database.seed_organization("alpha-lab").await?;
    let first_store = database.connect().await?;
    let second_store = database.connect().await?;
    let first_gateway = build_router(test_state(first_store.clone()));
    let second_gateway = build_router(test_state(second_store.clone()));
    let first_intent_id = "01J0000000000000000000M200";
    let second_intent_id = "01J0000000000000000000M300";
    let nonce = "nonce-ds036-shared-binding";
    let barrier = Arc::new(Barrier::new(3));

    let first = {
        let barrier = Arc::clone(&barrier);
        tokio::spawn(async move {
            barrier.wait().await;
            first_gateway
                .oneshot(signed_post_intent_request(
                    sample_intent_json(first_intent_id, "12.50"),
                    nonce,
                    AUDIENCE,
                    ENVIRONMENT,
                ))
                .await
        })
    };
    let second = {
        let barrier = Arc::clone(&barrier);
        tokio::spawn(async move {
            barrier.wait().await;
            second_gateway
                .oneshot(signed_post_intent_request(
                    sample_intent_json(second_intent_id, "11.50"),
                    nonce,
                    AUDIENCE,
                    ENVIRONMENT,
                ))
                .await
        })
    };
    barrier.wait().await;

    let (first, second) = tokio::join!(first, second);
    let mut winner = None;
    for response in [first??, second??] {
        if response.status() == StatusCode::OK {
            let decision = body_json(response).await?;
            assert!(winner
                .replace(decision["intent_id"].as_str().unwrap().to_owned())
                .is_none());
        } else {
            error_json(response, StatusCode::CONFLICT, "IDENTITY_NONCE_REPLAY").await?;
        }
    }
    let winner = winner.expect("exactly one conflicting Nonce binding must commit");

    first_store.close().await;
    second_store.close().await;
    let restarted_store = database.connect().await?;
    let chain = restarted_store
        .load_verified_audit_chain("alpha-lab")
        .await?;
    assert_eq!(
        chain
            .iter()
            .filter(|stored| stored.event.event_type == EventType::DecisionRecorded)
            .count(),
        1
    );
    assert_eq!(
        chain
            .iter()
            .filter(|stored| stored.event.event_type == EventType::ReplayDetected)
            .count(),
        1
    );
    for intent_id in [first_intent_id, second_intent_id] {
        let decision = restarted_store
            .load_finalized_decision("alpha-lab", intent_id)
            .await?;
        assert_eq!(decision.is_some(), intent_id == winner);
    }
    assert_eq!(database.business_record_counts().await?, (1, 1, 1, 1, 1, 8));

    restarted_store.close().await;
    database.destroy().await?;
    Ok(())
}
