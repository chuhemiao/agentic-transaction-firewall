# fuzz

**Status:** the public Intent boundary is implemented as an executable DS-037
gate. Adapter, Policy Context, calldata and Audit targets remain owned by the
phases that implement those external contracts (see `docs/PRD.md` §28.4).

`fuzz_targets/intent.rs` feeds arbitrary bytes to `atf_intent::validate`.
Invalid UTF-8, JSON, Schema, semantic or Profile input must return without a
panic; accepted input must serialize Amount as a JSON string and reproduce the
same typed value and canonical hash after validation. The checked-in corpus
contains one valid Intent plus malformed JSON, numeric money and an unknown
core-field rejection.

The runner requires `cargo-fuzz 0.13.2` and a nightly compiler. It copies seeds
to a temporary writable corpus, limits individual inputs to five seconds and
the whole smoke to 15 seconds by default (configurable from 1 through 60):

```bash
rustup toolchain install nightly-2026-08-01 --component llvm-tools-preview
cargo +nightly-2026-08-01 install cargo-fuzz --locked --version 0.13.2
RUSTUP_TOOLCHAIN=nightly-2026-08-01 ./scripts/test-fuzz.sh
ATF_FUZZ_MAX_TOTAL_TIME_SECONDS=60 \
RUSTUP_TOOLCHAIN=nightly-2026-08-01 ./scripts/test-fuzz.sh
```

CI installs the pinned cargo-fuzz release and selects the dated nightly
explicitly because the main workspace intentionally remains on stable Rust.
