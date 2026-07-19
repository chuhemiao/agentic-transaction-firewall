use serde_json::Value;
use sha2::{Digest, Sha256};

/// Recursively sort every JSON object's keys, explicitly, regardless of
/// which concrete map type `serde_json::Value::Object` happens to use.
///
/// `serde_json`'s `Map` is a `BTreeMap` (sorted) only when the
/// `preserve_order` feature is off *for every crate in the build* — Cargo
/// unifies features across the whole dependency graph, so if any dependency
/// anywhere turns `preserve_order` on (in this workspace: `jsonschema`/
/// `cedar-policy` pull it in via `serde_with`), `Value::Object` silently
/// becomes an insertion-order-preserving map for every crate that touches
/// `serde_json::Value`, including this one. Relying on the default was a
/// latent bug the first time this logic was written (in `atf-intent`): it
/// worked when that crate was tested in isolation and broke under `cargo
/// test --all-targets` for the whole workspace. Sorting explicitly here
/// makes canonical hashing correct independent of that flag — every crate
/// that needs a deterministic hash over JSON (`atf-intent`, `atf-audit`)
/// shares this one implementation instead of re-deriving the same fix.
pub fn sort_json_keys(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map
                .into_iter()
                .map(|(k, v)| (k, sort_json_keys(v)))
                .collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(entries.into_iter().collect())
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sort_json_keys).collect()),
        other => other,
    }
}

/// Hex-encoded SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorts_nested_object_keys() {
        let value = serde_json::json!({"zebra": 1, "alpha": {"zoo": 1, "aardvark": 2}});
        let sorted = sort_json_keys(value);
        let keys: Vec<&String> = sorted.as_object().unwrap().keys().collect();
        assert_eq!(keys, vec!["alpha", "zebra"]);
        let nested_keys: Vec<&String> = sorted["alpha"].as_object().unwrap().keys().collect();
        assert_eq!(nested_keys, vec!["aardvark", "zoo"]);
    }

    #[test]
    fn sorts_objects_nested_in_arrays() {
        let value = serde_json::json!([{"b": 1, "a": 2}]);
        let sorted = sort_json_keys(value);
        let keys: Vec<&String> = sorted[0].as_object().unwrap().keys().collect();
        assert_eq!(keys, vec!["a", "b"]);
    }

    #[test]
    fn sha256_hex_is_stable_and_64_hex_chars() {
        let a = sha256_hex(b"hello");
        let b = sha256_hex(b"hello");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, sha256_hex(b"goodbye"));
    }
}
