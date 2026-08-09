# Versioned Risk Rule Sets

DS-021 replaces implicit process defaults with one closed, executable Risk
Rule Set artifact. The reference artifact is `risk-rules/default.json`; its
public contract is `schemas/risk-rule-set.schema.json`.

## Canonical identity

`atf-risk::RiskRuleSet` rejects unknown fields, unsupported format/engine
versions, invalid amounts, out-of-range thresholds, non-canonical deny lists
and invalid history windows. Files must be regular, non-symlink UTF-8 files no
larger than 64 KiB.

After typed parsing and semantic validation, ATF serializes the complete
document with recursively sorted JSON object keys. The Rule Set hash is the
lowercase SHA-256 digest of:

```text
ATF_RISK_RULE_SET_V1\0 || canonical_json_bytes
```

The document binds `rule_set_version`, `engine_version`, every rule's enabled
state and severity, all thresholds and deny lists, missing-data behavior, the
duplicate-purchase window, the daily-spend limit/valuation asset/window/
accounting boundary, and the first-destination normalizer/boundary. Reordering JSON object
keys does not change the hash; any decision-affecting field change does.

Every `RiskEvaluation` owns the exact `rule_set_version`, `rule_set_hash`,
typed `RiskHistorySnapshot` and findings. Gateway `RiskEvaluated` evidence records the same pair for both
`SUCCEEDED` and `NOT_RUN`; old version-1 Audit payloads without the pair remain
decodable, while a partial version/hash pair is invalid.

## Missing data and accounting

Optional-input rules declare either:

- `FINDING`: emit the configured severity when required data is absent or
  unusable;
- `NOT_APPLICABLE`: emit no finding because the deployment explicitly treats
  the missing field as outside that rule.

The reference artifact uses `FINDING` for missing `max_fee` and vendor median,
so absent data does not silently preserve Permit. DS-024 makes this mandatory
for every enabled `vendor_price_deviation` rule; `NOT_APPLICABLE` is accepted
there only while that rule is disabled.

History rules must declare exactly one boundary:

- `REQUESTED` — `IntentReceived`;
- `PERMITTED` — `DecisionRecorded(PERMIT)`;
- `EXECUTED` — `ExecutionConfirmed`;
- `SETTLED` — `SettlementVerified`.

The current duplicate-purchase rule uses `PERMITTED` over 86,400 seconds.
DS-028 captures an indexed, repeatable-read query bounded by organization,
Agent, resource, current Intent, evaluation window and repository sequence; it
returns at most one prior matching `DecisionRecorded(PERMIT)`. The complete
query and optional result are canonical Evaluation/Audit evidence. Future
execution/settlement query families must retain the same explicit boundary and
immutable subject binding.

DS-029 adds `daily_cumulative_spend` as a backward-compatible optional Rule
Set family; old artifacts without it retain their canonical bytes/hash and
disable the rule. The reference v1.1.0 artifact enables a High finding at
25,000 USDC over 86,400 seconds using the `PERMITTED` boundary. Store records
the exact organization, Agent, current Intent, valuation asset, window and
repository boundary, then groups prior amounts by bound asset with PostgreSQL
`NUMERIC`. At most 256 asset groups are admitted to evidence. The current
Intent is added in Risk; same-asset values require no quote, while cross-asset
values require exactly one fresh, verified, organization/base/quote-scoped
direct `ATF_ENRICHED` `ASSET_QUOTE` rate. Missing/ambiguous/untrusted quotes,
legacy Decisions without an asset, overflow and precision loss emit the
configured restrictive finding rather than silently preserving Permit.

DS-030 adds `first_time_destination` as another backward-compatible optional
family. The reference v1.2.0 artifact enables a High finding with the exact
`atf.agent-commerce.payment.destination.eip155` normalizer version `1` and
`PERMITTED` accounting. Its query is organization-wide by design and binds the
exact Profile ID/version, current Intent, normalized destination, evaluation
time and repository boundary. Only a prior verified
`DecisionRecorded(PERMIT)` establishes familiarity. A prior DENY or another
organization does not; invalid checksum, unsupported namespace or any
unavailable normalization emits `FIRST_DESTINATION_NORMALIZATION_FAILED`
instead of silently preserving Permit. With the current High severity, a first
destination yields Review; Critical configuration yields Deny.

## Runtime selection and limits

Gateway requires `ATF_RISK_RULE_SET_PATH` and fails startup if the artifact is
missing, invalid, or not present as the exact audited durable archive for its
organization/environment. `atf risk install` validates and archives a Rule
Set through migration 0009; the installer must currently hold
`policy_author` or `org_admin`. `atf evaluate` accepts `--risk-rule-set` and defaults to
the reference file. Gateway evaluates stateless and history rules through
`evaluate_context` after the immutable Context has been persisted. The
evaluator obtains time, verified Evidence and repository boundary from that
Context, verifies the supplied typed history snapshot and returns the
version/hash plus exact query/result in canonical Evaluation and Audit evidence.

DS-026 makes the artifact durable and organization/environment-scoped so
Original Replay never substitutes a process default. DS-027 requires the same
exact archive identity for explicit Counterfactual selection and stores a
foreign-key-bound non-authoritative result. DS-022 supplies
provenance-bearing Evidence and the privileged-context firewall:
the vendor rule no longer reads Agent context and requires fresh verified,
scope-bound ATF evidence. DS-023 persists the exact Evaluation Context;
DS-024 removes the former clock/time/context convenience APIs and rejects
Intent, Rule Set or history-query substitutions before rule execution. DS-028
removes `atf-risk`'s Audit dependency; Store alone performs the bounded durable
query, and Replay reconstructs it at the original Context boundary.
DS-029 extends that same snapshot with the daily aggregate; parallel completed
Permits are visible to the next query, and both Replay modes regenerate the
aggregate at the original sequence/hash boundary.
DS-030 extends it again with the exact first-destination query/result. Store
re-verifies the selected typed event and Decision/Intent binding and re-runs
the normalizer, so indexed text alone cannot establish familiarity.
