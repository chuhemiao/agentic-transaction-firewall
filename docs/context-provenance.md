# Context Provenance and Trusted Evidence

Status: DS-022 implemented (2026-08-08); durable snapshot persistence is DS-023

Authority: `docs/PRD.md` §4.2.7, §12.3, §12.5 and §12.6

## Objective

Decision-affecting external values must be distinguishable from Agent hints,
integrity checked, fresh at the evaluation time and authorized by an explicit
local trust policy. A self-declared source name never grants authority.

DS-022 defines the evidence envelope and the Risk privileged-context firewall.
DS-023 will persist the resulting immutable Evaluation Context snapshot; DS-024
will remove the remaining evaluator convenience APIs that sample wall-clock
time.

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

Verification rejects malformed identifiers/timestamps/value shapes, hash
mismatch, unlisted sources or kinds, missing/unknown/invalid signatures and
non-fresh evidence. `VerifiedEvidence` cannot be constructed directly by a
caller; it is returned only by successful verification.

`RiskContext` records the canonical hash of the Intent from which it was
constructed. Reusing that context with any different Intent fails closed, so
callers cannot bypass Agent-key classification by substituting a context built
for another request.

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

An Agent value cannot overwrite a verified value. Without a verified value,
ordinary absence follows the Rule Set's declared missing-data behavior;
present-but-untrusted, stale, tampered, ambiguous, wrongly scoped or invalid
evidence always emits an explicit fail-closed insufficient-data finding.

## Verification

DS-022 is complete only when tests prove:

1. the public Schema and Rust type reject unknown/invalid fields and JSON
   numeric values;
2. canonical hash mutation and object-order behavior are deterministic;
3. source/kind allowlists, freshness and strict Ed25519 verification execute;
4. Agent price/balance/position/spend/reputation/simulation keys cannot become
   trusted inputs or overwrite verified evidence;
5. stale, tampered, unsigned-required, wrongly scoped and ambiguous evidence
   produces explicit restrictive Risk findings;
6. the full repository Definition of Done and real CLI/Gateway smoke paths are
   clean.
