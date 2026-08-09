# Transaction Intent profiles

This document fixes the currently supported profile contract. The common
Transaction Intent envelope remains defined by `schemas/transaction-intent.schema.json`
and PRD §9; passing that common shape alone does not mean ATF understands the
financial action.

## Profile selection

The current release supports exactly one derived profile:

| Profile ID | Version | `spec_version` | Action selector |
|---|---:|---:|---|
| `atf.agent-commerce.payment` | `1.0` | `1.0` | `payment/purchase_api_resource` |

The profile is derived from the version, action category, and operation; the
caller cannot assert a different profile in `context` or `metadata`. Every
other action/operation pair returns `UNSUPPORTED_INTENT_PROFILE` before
durable admission and before Policy/Risk. `atf_intent::validate_profile`
returns the stable ID/version so a later Evaluation/Decision contract can bind
it without guessing.

## Agent-Commerce Payment v1.0

This is a protocol-neutral on-chain payment for purchasing a typed resource.
The x402 fixture uses it, but x402 payment proofs, service-delivery evidence,
and Adapter behavior remain the RA-005 profile extension and are not implied
by this profile.

Required relationships:

1. `resource.protocol`, `resource.resource_id`, and
   `resource.resource_type` identify what is purchased.
2. `transaction.network` is a CAIP-2 chain ID.
3. `transaction.asset` is a CAIP-19 asset type or asset ID whose chain ID
   exactly equals `transaction.network`.
4. `transaction.destination` is a CAIP-10 account ID whose chain ID exactly
   equals `transaction.network`.
5. `transaction.contract`, `calldata_hash`, `slippage_bps`, and `leverage`
   must be absent/null. Those fields belong to Contract Call or trading
   profiles and cannot be smuggled into a Payment.
6. Optional `max_fee` is denominated in `transaction.asset`. The v1 envelope
   has no trusted `fee_asset`; a value with another fee asset is unsupported,
   and an extension field cannot override this rule.

CAIP strings in the signed Intent are case-sensitive. ATF validates the standard component lengths
and character sets, requires percent escapes to be complete uppercase hex
octets, and never trims, case-folds, decodes, or canonicalizes an identifier.
Binding the exact submitted bytes keeps the Intent hash deterministic.
CAIP-10 does not require one universal canonicalization and advises consumers
to handle deduplication. DS-030 therefore derives a separate, versioned history
key for the Payment Profile without changing those signed bytes. Normalizer
`atf.agent-commerce.payment.destination.eip155` version `1` accepts legacy
all-lowercase or valid EIP-55 checksum-case `eip155:<decimal-chain-id>:0x<40
hex>` values and emits a lowercase same-chain key. Invalid checksum,
non-canonical chain reference and unsupported namespaces remain explicit
unavailable Risk evidence. Asset-registry validation remains a later
protocol/Adapter concern.

Stable profile error codes are `UNSUPPORTED_INTENT_PROFILE`,
`PROFILE_FIELD_REQUIRED`, `PROFILE_FIELD_FORBIDDEN`, `NETWORK_ID_INVALID`,
`ASSET_ID_INVALID`, `ASSET_NETWORK_MISMATCH`, `DESTINATION_ID_INVALID`, and
`DESTINATION_NETWORK_MISMATCH`. Violations are ordered as resource, network,
asset, destination, then forbidden fields.

The machine-readable structural companion is
`schemas/profiles/payment-intent-v1.schema.json`. Consumers validate it
together with the common Schema. Cross-field chain equality and stable error
codes are enforced in Rust rather than relying only on JSON Schema.

## Versioning

Changing the selector, field ownership, CAIP interpretation, fee denomination,
or required relationships requires a new profile version and conformance
fixtures. Adding another action requires a new explicit dispatcher branch;
Schema enumeration alone never enables it.

## Normative identifier sources

- [CAIP-2 Blockchain ID](https://standards.chainagnostic.org/CAIPs/caip-2)
  defines `namespace:reference` and is Final.
- [CAIP-10 Account ID](https://standards.chainagnostic.org/CAIPs/caip-10)
  prefixes an account address with a CAIP-2 chain ID and is Final.
- [EIP-55 Mixed-case checksum address encoding](https://eips.ethereum.org/EIPS/eip-55)
  defines the Keccak-based checksum used by the version-1 EIP-155 history
  normalizer; the signed CAIP-10 value itself remains unchanged.
- [CAIP-19 Asset Type and Asset ID](https://standards.chainagnostic.org/CAIPs/caip-19)
  prefixes asset namespace/reference with a CAIP-2 chain ID. It is currently
  marked Review, so ATF pins the cited syntax through profile version `1.0`
  rather than silently following future changes.
