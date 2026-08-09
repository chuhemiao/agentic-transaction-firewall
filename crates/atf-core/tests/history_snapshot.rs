use std::str::FromStr;

use atf_core::{
    AccountingBoundary, DuplicatePurchaseHistory, DuplicatePurchaseMatch, DuplicatePurchaseQuery,
    RepositorySnapshot, RiskHistorySnapshot, Timestamp,
};

fn at(value: &str) -> Timestamp {
    Timestamp::from_str(value).unwrap()
}

fn repository() -> RepositorySnapshot {
    RepositorySnapshot::new("audit-chain:alpha-lab:42", 42, "a".repeat(64)).unwrap()
}

fn query() -> DuplicatePurchaseQuery {
    DuplicatePurchaseQuery::new(
        "alpha-lab",
        "research-agent-01",
        "dataset-01",
        "01J0000000000000000000NOW0",
        at("2026-08-09T12:00:00Z"),
        86_400,
        AccountingBoundary::Permitted,
    )
    .unwrap()
}

#[test]
fn snapshot_records_exact_query_and_bounded_result() {
    let prior = DuplicatePurchaseMatch::new(
        "01J0000000000000000000OLD0",
        "01J0000000000000000000DEC0",
        "01J0000000000000000000EVT0",
        39,
        at("2026-08-09T11:00:00Z"),
    )
    .unwrap();
    let duplicate = DuplicatePurchaseHistory::new(query(), Some(prior.clone())).unwrap();
    let snapshot = RiskHistorySnapshot::new(repository(), Some(duplicate)).unwrap();

    assert_eq!(snapshot.repository().through_sequence(), 42);
    let recorded = snapshot
        .duplicate_purchase()
        .expect("enabled duplicate query is recorded");
    assert_eq!(recorded.query().window_start(), at("2026-08-08T12:00:00Z"));
    assert_eq!(recorded.result(), Some(&prior));

    let encoded = serde_json::to_value(&snapshot).unwrap();
    assert_eq!(
        encoded["duplicate_purchase"]["query"]["accounting_boundary"],
        "PERMITTED"
    );
    assert_eq!(
        encoded["duplicate_purchase"]["result"]["boundary_sequence"],
        39
    );
}

#[test]
fn snapshot_rejects_results_outside_the_query_or_repository_boundary() {
    for prior in [
        DuplicatePurchaseMatch::new(
            "01J0000000000000000000OLD0",
            "01J0000000000000000000DEC0",
            "01J0000000000000000000EVT0",
            43,
            at("2026-08-09T11:00:00Z"),
        )
        .unwrap(),
        DuplicatePurchaseMatch::new(
            "01J0000000000000000000NOW0",
            "01J0000000000000000000DEC0",
            "01J0000000000000000000EVT0",
            39,
            at("2026-08-09T11:00:00Z"),
        )
        .unwrap(),
        DuplicatePurchaseMatch::new(
            "01J0000000000000000000OLD0",
            "01J0000000000000000000DEC0",
            "01J0000000000000000000EVT0",
            39,
            at("2026-08-08T11:59:59.999Z"),
        )
        .unwrap(),
        DuplicatePurchaseMatch::new(
            "01J0000000000000000000OLD0",
            "01J0000000000000000000DEC0",
            "01J0000000000000000000EVT0",
            39,
            at("2026-08-09T12:00:00.001Z"),
        )
        .unwrap(),
    ] {
        let duplicate = DuplicatePurchaseHistory::new(query(), Some(prior)).unwrap();
        assert!(RiskHistorySnapshot::new(repository(), Some(duplicate)).is_err());
    }
}

#[test]
fn snapshot_contract_rejects_unknown_fields() {
    let snapshot = RiskHistorySnapshot::new(repository(), None).unwrap();
    let mut encoded = serde_json::to_value(snapshot).unwrap();
    encoded
        .as_object_mut()
        .unwrap()
        .insert("untrusted".into(), serde_json::json!(true));

    assert!(serde_json::from_value::<RiskHistorySnapshot>(encoded).is_err());
}
