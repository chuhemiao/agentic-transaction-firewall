# Context Provenance and Trusted Evidence

Status: DS-022 through DS-024 implemented; DS-028 history boundary integrated (2026-08-09)

Authority: `docs/PRD.md` §4.2.7, §12.3, §12.5 and §12.6

## Objective

Decision-affecting external values must be distinguishable from Agent hints,
integrity checked, fresh at the evaluation time and authorized by an explicit
local trust policy. A self-declared source name never grants authority.

DS-022 defines the evidence envelope and the Risk privileged-context firewall.
DS-023 persists the exact verified envelopes, trust-policy identity, Agent
context hash and evaluation time inside the immutable Evaluation Context.
DS-024 makes that persisted Context the evaluator authority: Policy and Risk
have no clock-sampling or separately supplied privileged-input entry points.

## Evidence contract

Every `EvidenceEnvelope` is a closed version-1 document containing:

- an `EvidenceKind` and `EvidenceSource`;
- a bounded canonical `source_id`;
- `observed_at` and exclusive `expires_at` timestamps;
- a JSON value that contains no JSON numeric values (financial quantities use
  canonical decimal strings);
- optional integer `confidence_bps` in `0..=10000`;
- a lowercase SHA-256 `evidence_hash`;
- an optional versioned Ed25519 proof with a canonical Key ID.

The evidence hash is:

```text
SHA-256("ATF_EVIDENCE_V1\0" || canonical_evidence_payload)
```

The payload contains every field above except `evidence_hash` and `signature`,
with JSON object keys recursively sorted. The signature uses a separate
domain, binds the Key ID and exact evidence hash, and is verified strictly
against the configured public key.

Freshness is derived from the one caller-selected evaluation time:

- `NOT_YET_VALID` when evaluation precedes `observed_at`;
- `FRESH` while `observed_at <= evaluation_time < expires_at`;
- `STALE` at or after `expires_at`.

## Trust boundary

`EvidenceTrustPolicy` is deployment-owned configuration. Each entry binds an
exact source class and source ID to an allowlist of evidence kinds, optional
Ed25519 public keys and an explicit signature requirement. Duplicate trust
entries and any attempt to trust `AGENT_PROVIDED` fail closed.
The exact ordered source/kind/signature/key authorization set has a
domain-separated `ATF_EVIDENCE_TRUST_POLICY_V1` canonical hash.

Verification rejects malformed identifiers/timestamps/value shapes, hash
mismatch, unlisted sources or kinds, missing/unknown/invalid signatures and
non-fresh evidence. `VerifiedEvidence` cannot be constructed directly by a
caller; it is returned only by successful verification and internally retains
the actual verifier policy hash. Evaluation Context construction rejects a
claimed trust-policy reference that differs from any retained verifier hash.

Policy and Risk rederive the Intent hash and Profile and verify the Context's
Agent-context hash before execution. Policy also verifies environment, active
time and exact Bundle ID/version/hash. Risk verifies the exact Rule Set
engine/version/hash and requires its typed `RiskHistorySnapshot` repository
boundary to equal the `RepositorySnapshot` named by Context. The duplicate
query must also match the Intent's organization/Agent/resource/current ID, the
Context time, and the Rule Set window/accounting boundary. A different Intent,
artifact, query or history boundary fails closed before any rule runs.

## Privileged-context firewall

The following input classes are privileged: price, balance, position,
leverage, cumulative spend, protocol risk, address reputation, market-data
freshness and simulation result. Raw Intent `context` remains classified as
`AGENT_PROVIDED`; keys representing those classes are never read as trusted
Risk values.

The current vendor-deviation rule accepts only a `PRICE` envelope from an
allowlisted `ATF_ENRICHED` source whose typed value binds:

- metric `HISTORICAL_VENDOR_MEDIAN`;
- exact Organization ID;
- exact resource ID;
- exact asset;
- a positive canonical `Amount` string.

An Agent value cannot overwrite a verified value because the Risk evaluator
never reads privileged keys from raw Intent context. Only Evidence already
verified and embedded in the Context enters its internal typed input. When the
vendor rule is enabled, Rule Set validation requires `missing_data=FINDING`,
so absence cannot silently preserve Permit. Ambiguous, wrongly scoped or
invalid typed values emit an explicit fail-closed insufficient-data finding;
stale, tampered or untrusted envelopes cannot enter a valid Context.

## Verification

The DS-022 through DS-024 boundary is covered by tests that prove:

1. the public Schema and Rust type reject unknown/invalid fields and JSON
   numeric values;
2. canonical hash mutation and object-order behavior are deterministic;
3. source/kind allowlists, freshness and strict Ed25519 verification execute;
4. Agent price/balance/position/spend/reputation/simulation keys cannot become
   trusted inputs or overwrite verified evidence;
5. stale, tampered and unsigned-required evidence cannot enter a Context, while
   wrongly scoped and ambiguous persisted values produce restrictive findings;
6. the same Context plus recorded bounded history produces byte-equivalent
   Policy/Risk output, wall-clock and post-snapshot Audit state cannot affect
   it, and artifact/query/history mismatch fails closed;
7. the full repository Definition of Done and real CLI/Gateway smoke paths are
   clean.
