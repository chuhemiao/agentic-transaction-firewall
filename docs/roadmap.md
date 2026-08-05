# Roadmap

This is the security-delivery view of the roadmap. `README.md` remains the
live feature-status summary; `docs/PRD.md` §31 remains the product plan. The
acceptance criteria and evidence for every open area are in
`docs/audit-gap-matrix.md`. The ordering rationale is recorded in
`docs/decisions/0001-durable-shadow-before-enforce.md`.

## Current release: Durable Shadow Mode

- [ ] P0.1 PostgreSQL persistence for accepted Intents, Decisions, and the
  append-only Audit chain.
- [~] P0.2 Intent lifecycle state machine. `IntentReceived`,
  `PolicyEvaluated`, `RiskEvaluated`, and `DecisionRecorded` exist; identity,
  simulation, approval, execution, settlement, expiry, and cancellation
  transitions do not.
- [x] P0.3 Record every gateway outcome as `DecisionRecorded`, bound to the
  Intent hash. Duplicate-purchase history counts only same-organization
  `PERMIT` decisions; DENY does not poison later requests.
- [ ] P0.4 Durable, concurrent idempotency and replay protection.
- [ ] P0.5 Domain-separated Agent identity envelopes wired before Policy and
  Risk.
- [ ] P0.6 Versioned `EvaluationContext`; remove direct wall-clock and
  untrusted context reads from decision-making rules.
- [ ] P0.7 Original and counterfactual deterministic replay.
- [ ] P0.8 Context provenance, freshness, and trusted enrichment.
- [ ] P0.9 Versioned, hashed, scoped, validated Policy Bundles.
- [ ] P0.10 Metrics and organization-scoped Audit query API.

No real wallet, exchange, approval, or execution integration starts before
Durable Shadow Mode is complete and re-audited.

## Later releases

- **Reference simulation/adapters:** Mock Simulator and Adapter first, then
  x402, Safe, and Hyperliquid behind conformance tests.
- **Approval and Enforce Mode:** approval binding, single-use execution
  grants, Kill Switch, settlement verification, and reconciliation.
- **Community:** TypeScript/Python SDKs, MCP middleware, and documentation
  site.
