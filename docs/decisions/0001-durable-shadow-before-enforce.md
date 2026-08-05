# ADR-0001: Complete Durable Shadow Mode before Enforce Mode

## Status

Accepted

## Date

2026-08-05

## Context

ATF is intended to authorize and explain AI Agent financial actions across
wallets, exchanges, payment protocols, and Treasury systems. The repository
already has a working evaluate-only Gateway, but the security audit found that
its accepted Intents, Decisions, Audit chain, replay history, and Agent keys are
process-local or incomplete. Durable idempotency, deterministic replay,
decision-input provenance, organization authentication, and strong Decision
binding do not yet exist.

Adding real Adapters or execution authority now would turn those control-plane
gaps into direct financial-loss paths. A compelling demo is not evidence that
an authorization system can survive restart, concurrency, replay, stale data,
or cross-organization attacks.

## Decision

ATF will complete and re-audit Durable Shadow Mode before implementing any
real-funds execution path.

Durable Shadow Mode requires:

1. Transactional PostgreSQL persistence for Intent, Evaluation, Decision,
   Idempotency, Nonce, and Audit state.
2. An explicit Intent lifecycle, declared Audit-chain scope, and
   organization-isolated queries.
3. Domain-separated Agent identity envelopes verified before Policy/Risk.
4. Versioned Evaluation Context, Policy Bundle, Risk Rule Set, Context
   Snapshot, and external evidence.
5. Original and counterfactual deterministic replay.
6. Context provenance/freshness enforcement and safe observability.
7. Closure of the relevant CRITICAL/HIGH audit gaps with executable evidence.

Simulator and Adapter work begins with Mock implementations only after this
gate. Review/Enforce Mode additionally requires Approval, single-use Execution
Grants, Kill Switch, Settlement Verification, Reconciliation, and another
security review. Execution remains absent or default-disabled until then.

## Alternatives Considered

### Build reference Adapters first

- Advantage: faster visible demos and ecosystem integrations.
- Rejected: adapters would create pressure to treat incomplete Decisions as
  executable authorization and would force persistence/replay semantics to be
  retrofitted around protocol-specific behavior.

### Keep the current in-memory Gateway for Shadow Mode

- Advantage: minimal operational complexity.
- Rejected: restart loss, multi-instance divergence, non-durable idempotency,
  and non-replayable decisions contradict the product's core audit promise,
  even when ATF does not execute funds.

### Implement Identity wiring before persistence

- Advantage: closes anonymous Agent submission earlier.
- Rejected as the delivery order: nonce replay, key lifecycle, revocation, and
  identity audit state must survive restart. The Identity feature will be built
  on the durable transaction boundary instead of adding more process-local
  state.

## Consequences

- PostgreSQL persistence and lifecycle semantics are the next vertical
  feature, ahead of new protocol integrations.
- The project may look less feature-rich in the short term, but every later
  Adapter shares one tested authorization and evidence model.
- README, Architecture, Threat Model, Roadmap, Gap Matrix, and PRD must clearly
  distinguish current behavior from target behavior.
- No release may claim production readiness merely because it is Shadow Mode;
  authentication, tenant isolation, bounded resources, recovery, and
  observability remain release requirements.
- Any proposal to introduce execution before the gate must supersede this ADR
  explicitly and include an updated threat model and security review.
