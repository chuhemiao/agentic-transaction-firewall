mod common;

use atf_gateway::build_router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::error::Error;
use tower::ServiceExt;

use common::{body_json, get_decision_request, post_intent_request, test_state, TestDatabase};

#[tokio::test]
async fn second_gateway_state_reads_the_first_states_committed_decision(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("restart").await?;
    database.seed_organization("alpha-lab").await?;

    let first_store = database.connect().await?;
    let first = build_router(test_state(first_store.clone()));
    let response = first
        .oneshot(post_intent_request("01J0000000000000000000R100", "12.50"))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let original = body_json(response).await?;
    first_store.close().await;

    let second_store = database.connect().await?;
    let second = build_router(test_state(second_store.clone()));
    let response = second
        .oneshot(get_decision_request(
            "01J0000000000000000000R100",
            "alpha-lab",
        ))
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await?, original);

    second_store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn readiness_is_unavailable_when_postgresql_is_closed() -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("readiness").await?;
    database.seed_organization("alpha-lab").await?;
    let store = database.connect().await?;
    let app = build_router(test_state(store.clone()));

    let response = app
        .clone()
        .oneshot(Request::builder().uri("/readyz").body(Body::empty())?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    store.close().await;
    let response = app
        .oneshot(Request::builder().uri("/readyz").body(Body::empty())?)
        .await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn requests_fail_closed_without_exposing_database_details() -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("unavailable_request").await?;
    database.seed_organization("alpha-lab").await?;
    let store = database.connect().await?;
    let app = build_router(test_state(store.clone()));
    store.close().await;

    let response = app
        .oneshot(post_intent_request("01J0000000000000000000V100", "12.50"))
        .await?;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body_json(response).await?["error"],
        "durable state is unavailable"
    );

    database.destroy().await?;
    Ok(())
}
