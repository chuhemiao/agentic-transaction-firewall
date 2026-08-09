## What / why

<!-- What does this change, and what problem does it solve? Reference PRD
section(s) if this implements or modifies specced behavior. -->

## Checklist

- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes
- [ ] `cargo test` passes
- [ ] `./scripts/test-security.sh` and `./scripts/test-rust-sast.sh` pass
- [ ] Added/updated tests for behavior changes
- [ ] Updated `docs/*.md` if externally-visible behavior changed
- [ ] No production secrets, private keys, or real credentials in this diff
- [ ] Security tool/Action/exception changes have code-owner review and a
      documented version, reason, owner, and expiry where applicable
- [ ] If this changes the Transaction Intent schema, Decision model, or
      Adapter interface: discussed in an issue first (link it below)

## Related issue

<!-- Link the issue this addresses, if any -->
