use std::path::Path;
use std::process::Command;

use atf_decision::Decision;

#[test]
fn real_evaluate_command_defaults_to_a_millisecond_aligned_time() {
    let repository_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new(env!("CARGO_BIN_EXE_atf"))
        .current_dir(repository_root)
        .args(["evaluate", "examples/x402-research-agent/intent.json"])
        .output()
        .expect("run the real atf binary");

    assert!(
        output.status.success(),
        "default evaluate command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let decision: Decision =
        serde_json::from_slice(&output.stdout).expect("evaluate prints a typed Decision");
    assert_eq!(
        decision
            .evaluation_time
            .as_datetime()
            .timestamp_subsec_nanos()
            % 1_000_000,
        0,
        "default evaluation time must satisfy the canonical millisecond contract"
    );
}
