mod support;

use atf_core::DecisionKind;
use atf_gateway::{build_metrics_router, build_router};
use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use sqlx::{Connection, Executor, PgConnection};
use std::error::Error;
use tower::ServiceExt;

use support::{
    body_json, error_json, post_intent_request, test_durable_policy_state, test_state, TestDatabase,
};

#[tokio::test]
async fn database_loss_keeps_liveness_up_but_rejects_readiness_and_admission(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("dependency_database").await?;
    database.seed_organization("alpha-lab").await?;
    let store = database.connect().await?;
    let state = test_state(store.clone());
    let app = build_router(state.clone());
    let metrics = build_metrics_router(state);
    store.close().await;

    let health = app
        .clone()
        .oneshot(Request::builder().uri("/healthz").body(Body::empty())?)
        .await?;
    assert_eq!(health.status(), StatusCode::OK);

    let ready = app
        .clone()
        .oneshot(Request::builder().uri("/readyz").body(Body::empty())?)
        .await?;
    assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);

    error_json(
        app.clone()
            .oneshot(post_intent_request("01J0000000000000000000F350", "12.50"))
            .await?,
        StatusCode::SERVICE_UNAVAILABLE,
        "DURABLE_STATE_UNAVAILABLE",
    )
    .await?;
    assert_eq!(database.business_record_counts().await?, (0, 0, 0, 0, 0, 0));
    assert_metric(&metrics, "DATABASE", 1).await?;

    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn missing_active_bundle_is_not_ready_and_finishes_as_a_durable_error(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("dependency_policy").await?;
    database.seed_organization("alpha-lab").await?;
    let store = database.connect().await?;
    let state = test_durable_policy_state(store.clone());
    let app = build_router(state.clone());
    let metrics = build_metrics_router(state);

    let ready = app
        .clone()
        .oneshot(Request::builder().uri("/readyz").body(Body::empty())?)
        .await?;
    assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);

    let response = app
        .clone()
        .oneshot(post_intent_request("01J0000000000000000000F351", "12.50"))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await?["decision"], "ERROR");

    let finalized = store
        .load_finalized_decision("alpha-lab", "01J0000000000000000000F351")
        .await?
        .expect("active Policy loss must terminate with durable fail-closed evidence");
    assert_eq!(finalized.decision.decision, DecisionKind::Error);
    assert_metric(&metrics, "ACTIVE_POLICY", 1).await?;

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn corrupt_audit_chain_rejects_before_a_new_intent_is_accepted() -> Result<(), Box<dyn Error>>
{
    let database = TestDatabase::create("dependency_audit_corrupt").await?;
    database.seed_organization("alpha-lab").await?;
    let store = database.connect().await?;
    let first_sequence = store
        .load_verified_audit_chain("alpha-lab")
        .await?
        .first()
        .expect("provisioning creates Audit evidence")
        .sequence;
    database
        .corrupt_audit_event_for_test("alpha-lab", first_sequence)
        .await?;
    let state = test_state(store.clone());
    let app = build_router(state.clone());
    let metrics = build_metrics_router(state);

    error_json(
        app.clone()
            .oneshot(post_intent_request("01J0000000000000000000F352", "12.50"))
            .await?,
        StatusCode::INTERNAL_SERVER_ERROR,
        "DURABLE_STATE_INTEGRITY_ERROR",
    )
    .await?;
    assert_eq!(database.business_record_counts().await?, (0, 0, 0, 0, 0, 0));
    assert_metric(&metrics, "AUDIT", 1).await?;

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn audit_append_failure_rolls_back_the_new_decision_and_never_returns_permit(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("dependency_audit_write").await?;
    database.seed_organization("alpha-lab").await?;
    database
        .execute_for_test(
            r#"
            CREATE FUNCTION reject_decision_recorded_for_test() RETURNS trigger
            LANGUAGE plpgsql AS $$
            BEGIN
                IF NEW.event_type = 'DecisionRecorded' THEN
                    RAISE EXCEPTION USING ERRCODE = '58000', MESSAGE = 'injected Audit append failure';
                END IF;
                RETURN NEW;
            END;
            $$;
            CREATE TRIGGER reject_decision_recorded_for_test
            BEFORE INSERT ON audit_events
            FOR EACH ROW EXECUTE FUNCTION reject_decision_recorded_for_test()
            "#,
        )
        .await?;
    let store = database.connect().await?;
    let state = test_state(store.clone());
    let app = build_router(state.clone());
    let metrics = build_metrics_router(state);

    error_json(
        app.clone()
            .oneshot(post_intent_request("01J0000000000000000000F353", "12.50"))
            .await?,
        StatusCode::SERVICE_UNAVAILABLE,
        "DURABLE_STATE_UNAVAILABLE",
    )
    .await?;
    assert!(store
        .load_finalized_decision("alpha-lab", "01J0000000000000000000F353")
        .await?
        .is_none());
    let (_, _, contexts, evaluations, decisions, _) = database.business_record_counts().await?;
    assert_eq!((contexts, evaluations, decisions), (1, 0, 0));
    assert_metric(&metrics, "DATABASE", 1).await?;

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn durable_lock_timeout_is_bounded_and_rejects_before_acceptance(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("dependency_lock").await?;
    database.seed_organization("alpha-lab").await?;
    let store = database.connect().await?;
    let state = test_state(store.clone());
    let app = build_router(state.clone());
    let metrics = build_metrics_router(state);
    let mut lock = PgConnection::connect(&database.url).await?;
    lock.execute("BEGIN").await?;
    lock.execute("LOCK TABLE decisions IN ACCESS EXCLUSIVE MODE")
        .await?;

    error_json(
        app.clone()
            .oneshot(post_intent_request("01J0000000000000000000F354", "12.50"))
            .await?,
        StatusCode::SERVICE_UNAVAILABLE,
        "DURABLE_STATE_UNAVAILABLE",
    )
    .await?;
    assert!(store
        .load_finalized_decision("alpha-lab", "01J0000000000000000000F354")
        .await?
        .is_none());
    assert_metric(&metrics, "LOCK", 1).await?;

    lock.execute("ROLLBACK").await?;
    lock.close().await?;
    let (reservations, intents, contexts, evaluations, decisions, _) =
        database.business_record_counts().await?;
    assert_eq!(
        (reservations, intents, contexts, evaluations, decisions),
        (0, 0, 0, 0, 0)
    );
    store.close().await;
    database.destroy().await?;
    Ok(())
}

async fn assert_metric(
    app: &axum::Router,
    dependency: &str,
    minimum: u64,
) -> Result<(), Box<dyn Error>> {
    let response = app
        .clone()
        .oneshot(support::operations_metrics_request())
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = String::from_utf8(to_bytes(response.into_body(), usize::MAX).await?.to_vec())?;
    let prefix = format!("atf_gateway_dependency_failures_total{{dependency=\"{dependency}\"}} ");
    let value = body
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or_default();
    assert!(
        value >= minimum,
        "expected {prefix}<count> >= {minimum}, metrics were:\n{body}"
    );
    Ok(())
}
