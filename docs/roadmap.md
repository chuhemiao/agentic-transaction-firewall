# Roadmap

This is the security-delivery view of the roadmap. `README.md` remains the
live feature-status summary; `docs/PRD.md` §31 remains the product plan. The
detailed dependency graph, task acceptance criteria and verification commands
are in [`../tasks/plan.md`](../tasks/plan.md); the one-item-at-a-time execution
queue is [`../tasks/todo.md`](../tasks/todo.md). Gap evidence remains in
`docs/audit-gap-matrix.md`, and the execution-last rationale is recorded in
`docs/decisions/0001-durable-shadow-before-enforce.md`.

## Current release: Durable Shadow Mode

The P0.x numbers identify product capabilities, not a literal implementation
order. The executable order is:

1. durable state and lifecycle (`DS-001`..`DS-007`);
2. strict Intent contract and authenticated/idempotent admission
   (`DS-008`..`DS-018`);
3. versioned Policy/Risk/Context before Decision binding and Replay
   (`DS-019`..`DS-027`);
4. stateful Risk, query/observability, operational hardening and re-audit
   (`DS-028`..`DS-040`).

- [x] BL-001 Restore the cargo-deny baseline without weakening wildcard,
  license, or source policy; pin CI to cargo-deny 0.20.2 semantics.

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

**Immediate next task:** `DS-001` — record the PostgreSQL transaction,
evaluator-recovery and per-organization Audit-chain contract in ADR-0002.

## Later releases

- **Reference simulation/adapters:** Mock Simulator and Adapter first, then
  x402, Safe, and Hyperliquid behind conformance tests.
- **Approval and Enforce Mode:** approval binding, single-use execution
  grants, Kill Switch, settlement verification, and reconciliation.
- **Community:** TypeScript/Python SDKs, MCP middleware, and documentation
  site.
