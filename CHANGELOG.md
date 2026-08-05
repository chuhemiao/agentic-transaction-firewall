# Changelog

All notable changes to this project are documented here.
This project has not yet made a tagged release.

## [Unreleased]

### Added

- `DecisionRecorded` Audit events on the gateway request path, including the
  canonical Intent hash and organization-scoped fields needed for lifecycle
  queries.
- A repository-backed security gap matrix and Durable Shadow Mode roadmap.
- Initial workspace skeleton per PRD §36: `atf-core`, `atf-intent`,
  `atf-policy`, `atf-decision`, `atf-cli`.
- Canonical Transaction Intent type, JSON Schema validation, canonical
  serialization and hashing.
- Minimal Cedar policy evaluation.
- `atf validate-intent` and `atf evaluate` CLI commands.
- CI workflow (fmt, clippy, test).
- Project governance and security docs (README, LICENSE, SECURITY,
  CONTRIBUTING, CODE_OF_CONDUCT).

### Changed

- Duplicate-purchase detection now counts only prior same-organization
  `DecisionRecorded(PERMIT)` events instead of every `IntentReceived` event.

### Security

- A previously denied request can no longer poison a later valid request by
  making it look like a duplicate purchase, and histories from different
  organizations no longer collide in that rule.
