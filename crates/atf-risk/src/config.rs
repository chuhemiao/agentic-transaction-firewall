use atf_core::Amount;

/// Thresholds for the MVP rule set (PRD §12.2). None of these have a
/// universal "correct" default — a single-transaction cap or a high-risk
/// network list is inherently org-specific — so anything without a safe,
/// broadly-applicable default is left disabled (`None` / empty) rather than
/// guessing a number that would silently gate real traffic.
#[derive(Debug, Clone)]
pub struct RiskConfig {
    /// Flag any transaction above this amount. Disabled by default.
    pub max_single_amount: Option<Amount>,
    /// Flag when `max_fee / amount` exceeds this many basis points.
    /// Default 500 bps (5%) — a generic "this fee looks disproportionate"
    /// heuristic, not tied to any specific network's real fee market.
    pub max_fee_ratio_bps: Option<u32>,
    /// Flag when `transaction.amount` deviates from
    /// `context.historical_vendor_median` (if present) by more than this
    /// many basis points. Default 3000 bps (30%), matching the x402
    /// Research Agent reference scenario (PRD §24.3.4).
    pub vendor_price_deviation_bps: Option<u32>,
    /// Case-insensitive network names to always flag. Empty by default.
    pub high_risk_networks: Vec<String>,
    /// Case-insensitive protocol names to always flag. Empty by default.
    pub high_risk_protocols: Vec<String>,
}

impl Default for RiskConfig {
    fn default() -> Self {
        Self {
            max_single_amount: None,
            max_fee_ratio_bps: Some(500),
            vendor_price_deviation_bps: Some(3000),
            high_risk_networks: Vec::new(),
            high_risk_protocols: Vec::new(),
        }
    }
}
