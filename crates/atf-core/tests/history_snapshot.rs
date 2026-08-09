use std::str::FromStr;

use atf_core::{
    AccountingBoundary, Amount, DailySpendAssetTotal, DailySpendHistory, DailySpendQuery,
    DuplicatePurchaseHistory, DuplicatePurchaseMatch, DuplicatePurchaseQuery, RepositorySnapshot,
    RiskHistorySnapshot, Timestamp,
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

fn daily_query() -> DailySpendQuery {
    DailySpendQuery::new(
        "alpha-lab",
        "agent-a",
        "01J0000000000000000000NOW0",
        "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
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

#[test]
fn daily_spend_snapshot_records_explicit_asset_tenant_and_boundary_scope() {
    let totals = vec![
        DailySpendAssetTotal::new("eip155:1/slip44:60", "2.50".parse::<Amount>().unwrap(), 1)
            .unwrap(),
        DailySpendAssetTotal::new(
            "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
            "20.00".parse::<Amount>().unwrap(),
            2,
        )
        .unwrap(),
    ];
    let daily = DailySpendHistory::new(daily_query(), totals, 1).unwrap();
    let snapshot = RiskHistorySnapshot::with_daily_spend(repository(), None, Some(daily)).unwrap();

    let encoded = serde_json::to_value(&snapshot).unwrap();
    assert_eq!(
        encoded["daily_cumulative_spend"]["query"]["organization_id"],
        "alpha-lab"
    );
    assert_eq!(
        encoded["daily_cumulative_spend"]["query"]["agent_id"],
        "agent-a"
    );
    assert_eq!(
        encoded["daily_cumulative_spend"]["query"]["valuation_asset"],
        "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
    );
    assert_eq!(
        encoded["daily_cumulative_spend"]["query"]["accounting_boundary"],
        "PERMITTED"
    );
    assert_eq!(
        encoded["daily_cumulative_spend"]["totals"][0]["amount"],
        "2.50"
    );
    assert_eq!(
        encoded["daily_cumulative_spend"]["unresolved_asset_decision_count"],
        1
    );
    assert_eq!(
        serde_json::from_value::<RiskHistorySnapshot>(encoded).unwrap(),
        snapshot
    );
}

#[test]
fn daily_spend_totals_must_be_positive_strictly_sorted_and_unique() {
    let first = DailySpendAssetTotal::new(
        "eip155:8453/slip44:60",
        "1.00".parse::<Amount>().unwrap(),
        1,
    )
    .unwrap();
    let second =
        DailySpendAssetTotal::new("eip155:1/slip44:60", "2.00".parse::<Amount>().unwrap(), 1)
            .unwrap();
    assert!(DailySpendHistory::new(daily_query(), vec![first, second], 0).is_err());

    assert!(DailySpendAssetTotal::new("eip155:8453/slip44:60", Amount::ZERO, 1,).is_err());
    assert!(DailySpendAssetTotal::new(
        "eip155:8453/slip44:60",
        "1.00".parse::<Amount>().unwrap(),
        0,
    )
    .is_err());
}

#[test]
fn daily_spend_snapshot_bounds_asset_group_cardinality() {
    let totals = (0..257)
        .map(|index| {
            DailySpendAssetTotal::new(
                format!("eip155:1/slip44:{index:03}"),
                "1.00".parse::<Amount>().unwrap(),
                1,
            )
            .unwrap()
        })
        .collect();

    assert!(DailySpendHistory::new(daily_query(), totals, 0).is_err());
}

#[test]
fn legacy_history_without_daily_spend_remains_byte_compatible() {
    let snapshot = RiskHistorySnapshot::new(repository(), None).unwrap();
    let encoded = serde_json::to_value(&snapshot).unwrap();

    assert!(encoded.get("daily_cumulative_spend").is_none());
    assert_eq!(
        serde_json::from_value::<RiskHistorySnapshot>(encoded).unwrap(),
        snapshot
    );
}
