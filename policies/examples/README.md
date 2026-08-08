# policies/examples

Validated example Policy Bundle exercised by `atf-cli evaluate` and by
`atf-policy`'s own tests. `manifest.json` binds the exact Cedar Schema, policy
file digests, `alpha-lab`/`development` scope, active window and canonical
Bundle hash. These policies are intentionally simple — they exist to
demonstrate the Intent -> Cedar mapping, not to be a production policy pack
(see `policies/trading`, `policies/treasury`, `policies/agent-payments` for
the not-yet-implemented per-scenario bundles from PRD §24).

## Context fields available to policies

`atf-policy` maps a `TransactionIntent` (PRD §9.2) onto a Cedar request as:

- `principal` = `Agent::"<principal.agent_id>"`
- `action` = `Action::"<action.category>/<action.operation>"`
- `resource` = `Resource::"<resource.resource_id>"`
- `context` = a record with (all optional fields omitted rather than null,
  since Cedar records have no null type):
  - `organization_id`, `user_id`, `agent_version`, `strategy_id`
  - `mandate_id`, `task_id`, `purpose`, `budget_id`, `human_authorized`
  - `protocol`, `venue`, `resource_type`
  - `network`, `asset`, `destination`, `contract`, `slippage_bps`
  - `amount`, `max_fee`, `leverage` — each a Cedar `decimal` extension value
    (up to 4 fractional digits), so policies can do
    `context.amount.lessThan(decimal("50000.0000"))` range comparisons.

## Files

- `manifest.json` — closed ATF Policy Bundle v1 manifest.
- `cedar-schema.json` — Cedar request/context contract used for strict policy
  and per-request validation.
- `payment-budget.cedar` — permits `payment/purchase_api_resource` up to a
  fixed per-request cap for one example organization.
- `require-human-authorization.cedar` — forbids anything where the intent's
  mandate was not human-authorized, regardless of what else permits it
  (Cedar's `forbid` always overrides `permit` — PRD §11.3.1).
- `signature.json` / `publisher-2026.pub` — deterministic, non-production
  detached proof/public-key fixtures for lifecycle tests and local smoke only.

Load the validated bundle with `atf-cli evaluate --policies policies/examples
--environment development`. See `docs/policy-bundles.md` for hashing and
validation details. The included public proof is test-only; production release
proofs must come from an external signing-key custody boundary following
`docs/policy-model.md`.
