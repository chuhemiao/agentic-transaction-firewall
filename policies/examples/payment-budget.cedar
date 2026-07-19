// Permit small x402-style payments for one example organization, matching
// the shape of the x402 Research Agent reference scenario (PRD §24.3),
// without any of that scenario's other rules (duplicate-purchase checks,
// vendor concentration, etc. — those belong to the Risk Engine, not Cedar,
// per PRD §11.2).
permit (
    principal,
    action == Action::"payment/purchase_api_resource",
    resource
)
when {
    context.organization_id == "alpha-lab" &&
    context.amount.lessThanOrEqual(decimal("20.0000"))
};
