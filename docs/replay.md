# Deterministic Replay

DS-026 implements **Original Replay**, DS-027 implements isolated
**Counterfactual Replay**, and DS-028..DS-030 make both reconstruct enabled
bounded Risk-history queries at the original repository boundary. Neither operation can
create, replace, or update an authoritative Evaluation or Decision.

## Authority and inputs

Both Replay commands require the current Operator to hold `auditor` or
`org_admin` for the requested organization. Authorization is checked before
input discovery and checked again in the final atomic record/Audit transaction.

Replay loads and verifies:

1. the admitted canonical Intent and its identity/admission evidence;
2. the finalized Evaluation, Decision, and immutable Evaluation Context;
3. the exact signed Policy Bundle identified by ID, version, hash,
   organization, environment, and evaluation time;
4. the exact canonical Risk Rule Set identified by engine version, Rule Set
   version, hash, organization, and environment;
5. exactly the Audit prefix named by the Context's sequence and head hash;
6. the typed bounded Risk-history query/result reconstructed at that boundary.

Migration 0009 adds the append-only `risk_rule_sets` archive. Installation
requires current `policy_author` or `org_admin` authority and atomically binds
canonical bytes, their artifact hash, the domain-separated Rule Set hash, the
installer, and a typed `RiskRuleSetStored` event. The Gateway now refuses to
start unless its configured Rule Set resolves to this exact audited archive.

## Reproduction contract

Policy is rerun against the original Context; Risk is rerun against that
Context plus the reconstructed bounded history snapshot. Their typed evidence
must equal the original Evaluation evidence. Decision merge
then reuses the original Decision ID; the complete canonical Decision bytes
and embedded `ATF_DECISION_V1` hash must be identical.

Success appends `OriginalReplayCompleted` with references to the original
Evaluation and Decision, both hashes, `matched: true`, and
`authoritative: false`. The original rows are not mutated and no replacement
rows are inserted.

Missing exact artifacts and modified canonical bytes/evidence fail closed.
Stable public CLI codes include:

- `REPLAY_AUTHORIZATION_DENIED`
- `REPLAY_POLICY_ARTIFACT_MISSING`
- `REPLAY_RISK_ARTIFACT_MISSING`
- `REPLAY_INPUT_TAMPERED`
- `REPLAY_EVALUATION_MISMATCH`
- `REPLAY_DECISION_MISMATCH`

## Counterfactual contract

Counterfactual Replay starts from the verified original Intent and immutable
Context snapshot. It retains the original evaluation time, Context snapshot
hash, verified Evidence, external availability facts and exact Audit-history
prefix, while the caller explicitly selects a Policy Bundle ID/version/hash
and Risk engine/Rule Set version/hash. At least one selected artifact must
differ from the original, and a selected Policy Bundle must be valid for the
original evaluation time; missing, incompatible or modified artifacts fail
closed without fallback to a process default.

The caller supplies or the CLI creates fresh Replay, Evaluation and Decision
IDs. Migration 0010 stores the derived Context, Counterfactual Evaluation and
Decision canonical bytes/hashes in `counterfactual_replays`, linked by foreign
keys to the original authoritative Evaluation/Decision and exact archived
artifacts. Database constraints and triggers enforce new identities,
`authoritative: false`, the exact changed-outcome relation, and rejection of
update/delete/truncate. The authoritative `evaluation_contexts`, `evaluations`
and `decisions` tables are never written.

Success atomically appends `CounterfactualReplayCompleted`. Its typed payload
binds original and Counterfactual lineage, Context/Evaluation/Decision hashes,
selected artifact identities, both outcomes, `outcome_changed`, actor and
`authoritative: false`. Restart reads reparse and recanonicalize all three
documents, verify their hashes and Decision binding, reload the selected
signed Policy/Risk archives, and require the matching Audit evidence.

Additional stable codes are:

- `REPLAY_SELECTED_ARTIFACT_MISSING`
- `REPLAY_COUNTERFACTUAL_CONFLICT`

## CLI

```bash
DATABASE_URL=postgres://... atf risk install risk-rules/default.json \
  --organization-id alpha-lab --environment development \
  --actor-id policy-author-1 --occurred-at 2026-08-08T11:31:00Z

DATABASE_URL=postgres://... atf replay original \
  --organization-id alpha-lab --intent-id 01J... \
  --actor-id auditor-1 --occurred-at 2026-08-08T12:05:00Z

DATABASE_URL=postgres://... atf replay counterfactual \
  --organization-id alpha-lab --intent-id 01J... \
  --actor-id auditor-1 --occurred-at 2026-08-08T12:06:00Z \
  --policy-bundle-id atf-example-payments --policy-version 1.1.0 \
  --policy-bundle-hash 0123...cdef \
  --risk-engine-version atf-risk-engine-v1 \
  --risk-rule-set-version risk-rules-2.0.0 \
  --risk-rule-set-hash fedc...3210
```

Counterfactual CLI output explicitly includes original/new Evaluation and
Decision IDs/hashes, exact selected versions/hashes, both outcomes,
`outcome_changed`, `authoritative: false`, and the Audit event ID.

The executable relation fixture and fail-closed cases are in
`conformance/replay-tests/original.json`,
`conformance/replay-tests/counterfactual.json`, and
`crates/atf-store/tests/replay.rs`.
