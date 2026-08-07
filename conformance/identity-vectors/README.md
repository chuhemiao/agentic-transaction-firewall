# conformance/identity-vectors

Cross-language fixtures for the Agent Identity Envelope contract in
`docs/identity-envelope.md`.

`atf-intent-v1.json` contains one complete Intent, canonical
`ATF_INTENT_V1` Envelope, compact UTF-8/hex signing bytes, RFC 8032 test key
material, and its deterministic Ed25519 signature. The signature was generated
independently with Node's built-in OpenSSL-backed `crypto.sign`; Rust verifies
the literal rather than generating its own expected value.

```bash
cargo test -p atf-identity --test envelope
```

Seeds in this directory are public test fixtures, never deployment secrets.
Changing a field, byte ordering rule, timestamp representation or domain is a
versioned protocol change and requires a new vector rather than rewriting v1.
