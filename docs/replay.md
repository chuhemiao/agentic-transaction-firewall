# Deterministic Replay

DS-026 implements **Original Replay** as a PostgreSQL-backed verification
operation. It does not create, replace, or update an authoritative Evaluation
or Decision.

## Authority and inputs

`atf replay original` requires the current Operator to hold `auditor` or
`org_admin` for the requested organization. Authorization is checked before
input discovery and checked again in the final Audit append transaction.

Replay loads and verifies:

1. the admitted canonical Intent and its identity/admission evidence;
2. the finalized Evaluation, Decision, and immutable Evaluation Context;
3. the exact signed Policy Bundle identified by ID, version, hash,
   organization, environment, and evaluation time;
4. the exact canonical Risk Rule Set identified by engine version, Rule Set
   version, hash, organization, and environment;
5. exactly the Audit prefix named by the Context's sequence and head hash.

Migration 0009 adds the append-only `risk_rule_sets` archive. Installation
requires current `policy_author` or `org_admin` authority and atomically binds
canonical bytes, their artifact hash, the domain-separated Rule Set hash, the
installer, and a typed `RiskRuleSetStored` event. The Gateway now refuses to
start unless its configured Rule Set resolves to this exact audited archive.

## Reproduction contract

Policy and Risk are rerun against the original Context and Audit prefix. Their
typed evidence must equal the original Evaluation evidence. Decision merge
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

Counterfactual Replay is deliberately separate: DS-027 will create new,
non-authoritative Evaluation/Decision identities with explicit lineage and
selected replacement artifact versions.

## CLI

```bash
DATABASE_URL=postgres://... atf risk install risk-rules/default.json \
  --organization-id alpha-lab --environment development \
  --actor-id policy-author-1 --occurred-at 2026-08-08T11:31:00Z

DATABASE_URL=postgres://... atf replay original \
  --organization-id alpha-lab --intent-id 01J... \
  --actor-id auditor-1 --occurred-at 2026-08-08T12:05:00Z
```

The executable relation fixture and fail-closed cases are in
`conformance/replay-tests/original.json` and
`crates/atf-store/tests/replay.rs`.
