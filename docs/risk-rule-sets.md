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
duplicate-purchase window and its accounting boundary. Reordering JSON object
keys does not change the hash; any decision-affecting field change does.

Every `RiskEvaluation` owns the exact `rule_set_version`, `rule_set_hash` and
findings. Gateway `RiskEvaluated` evidence records the same pair for both
`SUCCEEDED` and `NOT_RUN`; old version-1 Audit payloads without the pair remain
decodable, while a partial version/hash pair is invalid.

## Missing data and accounting

Optional-input rules declare either:

- `FINDING`: emit the configured severity when required data is absent or
  unusable;
- `NOT_APPLICABLE`: emit no finding because the deployment explicitly treats
  the missing field as outside that rule.

The reference artifact uses `FINDING` for missing `max_fee` and vendor median,
so absent data does not silently preserve Permit.

History rules must declare exactly one boundary:

- `REQUESTED` — `IntentReceived`;
- `PERMITTED` — `DecisionRecorded(PERMIT)`;
- `EXECUTED` — `ExecutionConfirmed`;
- `SETTLED` — `SettlementVerified`.

The current duplicate-purchase rule uses `PERMITTED` over 86,400 seconds. For
execution/settlement boundaries, the verified Audit chain joins the boundary
event to its immutable `IntentReceived` subject fields by Intent ID.

## Runtime selection and limits

Gateway requires `ATF_RISK_RULE_SET_PATH` and fails startup if the artifact is
missing or invalid. `atf evaluate` accepts `--risk-rule-set` and defaults to
the reference file. Gateway evaluates stateless and history rules at one
caller-selected evaluation time, then persists the version/hash in canonical
Evaluation and Audit evidence.

DS-021 does not yet make the artifact durable or organization-scoped, and it
does not make external context trustworthy. DS-022 adds provenance and the
privileged-context firewall; DS-023 persists the exact Evaluation Context;
DS-024 removes the remaining convenience APIs that sample wall-clock time.
