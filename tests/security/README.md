# DS-038 negative fixtures

These fixtures are inert and must never be built or shipped as ATF components:

- `vulnerable-lock` pins `time 0.1.44` so RustSec must report
  `RUSTSEC-2020-0071`.
- `rust-sast` contains one unsafe pointer dereference so the pinned Clippy gate
  must reject it under `-F unsafe-code`.

The synthetic Gitleaks value and expired exception policies are created only
inside a temporary directory by `scripts/test-security.sh`; no credential is
stored in the repository.
