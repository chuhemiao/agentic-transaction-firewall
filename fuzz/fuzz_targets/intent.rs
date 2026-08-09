#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(intent) = atf_intent::validate(raw) else {
        // Malformed, schema-invalid, semantically invalid and unsupported
        // inputs all fail closed through the same public parser boundary.
        return;
    };

    let original_hash = intent.canonical_hash();
    let encoded = serde_json::to_string(&intent).expect("a validated Intent must serialize");
    let encoded_value: serde_json::Value =
        serde_json::from_str(&encoded).expect("serialized Intent must remain JSON");
    assert!(
        encoded_value
            .pointer("/transaction/amount")
            .is_some_and(serde_json::Value::is_string),
        "financial amounts must never serialize as JSON numbers"
    );

    let reparsed = atf_intent::validate(&encoded)
        .expect("a validated Intent must survive its canonical typed round trip");
    assert_eq!(
        reparsed, intent,
        "typed Intent round trip changed the value"
    );
    assert_eq!(
        reparsed.canonical_hash(),
        original_hash,
        "typed Intent round trip changed the canonical hash"
    );
});
