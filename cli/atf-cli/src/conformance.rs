use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use atf_policy::{PolicyBundle, PolicyDecision};
use serde::Deserialize;

/// The Cedar-level decision a conformance case expects (PRD §11, §11.3.1) —
/// deliberately not ATF's own PERMIT/DENY/REVIEW/ERROR (`atf_decision::DecisionKind`):
/// this harness exercises the Policy Kernel in isolation, the same way
/// `conformance/policy-tests/README.md` describes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ExpectedDecision {
    Permit,
    Forbid,
}

#[derive(Debug, Deserialize)]
struct PolicyTestCase {
    name: String,
    /// Directory of `.cedar` files, resolved relative to the current
    /// working directory (matching `atf-cli evaluate --policies`).
    policies: PathBuf,
    intent: serde_json::Value,
    expect: ExpectedDecision,
}

struct CaseOutcome {
    name: String,
    passed: bool,
    detail: String,
}

/// Run every `*.json` conformance test case found directly inside `dir`
/// (not recursive) and print a pass/fail report. Returns `Err` if any case
/// failed or errored — so `atf policy test` can be used as a CI gate
/// (PRD §21, §27.4) via its exit code.
pub fn run(dir: &Path) -> Result<()> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("reading conformance test directory {}", dir.display()))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();

    if paths.is_empty() {
        anyhow::bail!(
            "no *.json conformance test cases found in {}",
            dir.display()
        );
    }

    let outcomes: Vec<CaseOutcome> = paths.iter().map(|path| run_case(path)).collect();
    let failed = outcomes.iter().filter(|o| !o.passed).count();

    for outcome in &outcomes {
        let mark = if outcome.passed { "ok" } else { "FAIL" };
        println!("[{mark}] {} - {}", outcome.name, outcome.detail);
    }
    println!(
        "{} passed, {failed} failed, {} total",
        outcomes.len() - failed,
        outcomes.len()
    );

    if failed == 0 {
        Ok(())
    } else {
        anyhow::bail!("{failed} conformance test case(s) failed")
    }
}

fn run_case(path: &Path) -> CaseOutcome {
    match run_case_inner(path) {
        Ok(outcome) => outcome,
        Err(err) => CaseOutcome {
            name: path.display().to_string(),
            passed: false,
            detail: format!("error: {err:#}"),
        },
    }
}

fn run_case_inner(path: &Path) -> Result<CaseOutcome> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading conformance test case {}", path.display()))?;
    let case: PolicyTestCase = serde_json::from_str(&raw)
        .with_context(|| format!("parsing conformance test case {}", path.display()))?;

    let intent_json = serde_json::to_string(&case.intent)?;
    let intent = atf_intent::validate(&intent_json)
        .map_err(|e| anyhow::anyhow!("intent in {}: {e}", path.display()))?;

    let bundle = PolicyBundle::from_dir(&case.policies)
        .with_context(|| format!("loading policy bundle {}", case.policies.display()))?;
    let outcome = bundle
        .evaluate(&intent)
        .map_err(|e| anyhow::anyhow!("evaluating {}: {e}", path.display()))?;

    let passed = matches!(
        (case.expect, outcome.decision),
        (ExpectedDecision::Permit, PolicyDecision::Permit)
            | (ExpectedDecision::Forbid, PolicyDecision::Forbid)
    );
    let detail = format!("expected {:?}, got {:?}", case.expect, outcome.decision);

    Ok(CaseOutcome {
        name: case.name,
        passed,
        detail,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const INTENT: &str = r#"{
        "spec_version": "1.0",
        "intent_id": "01J0000000000000000000TT00",
        "idempotency_key": "conformance-runner-test",
        "created_at": "2098-12-31T23:55:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "principal": { "organization_id": "alpha-lab", "agent_id": "research-agent-01" },
        "mandate": {
            "mandate_id": "mandate-001",
            "purpose": "test",
            "human_authorized": true
        },
        "action": { "category": "payment", "operation": "purchase_api_resource" },
        "resource": { "protocol": "x402", "resource_id": "btc-orderbook-2026-07-01" },
        "transaction": { "network": "base", "asset": "eip155:8453/erc20:0x0", "amount": "12.50" }
    }"#;

    const POLICY: &str = r#"
        permit (principal, action, resource);
    "#;

    /// Sets up `<tmp>/policies/permit-all.cedar` and returns the tmp root.
    fn setup(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "atf-cli-conformance-test-{tag}-{}",
            std::process::id()
        ));
        let policies_dir = root.join("policies");
        std::fs::create_dir_all(&policies_dir).unwrap();
        std::fs::write(policies_dir.join("permit-all.cedar"), POLICY).unwrap();
        root
    }

    fn write_case(root: &Path, file_name: &str, expect: &str) {
        let intent: serde_json::Value = serde_json::from_str(INTENT).unwrap();
        let case = serde_json::json!({
            "name": file_name,
            "policies": root.join("policies"),
            "expect": expect,
            "intent": intent,
        });
        std::fs::write(
            root.join(file_name),
            serde_json::to_string_pretty(&case).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn run_succeeds_when_every_case_matches_its_expectation() {
        let root = setup("all-pass");
        write_case(&root, "a.json", "permit");
        assert!(run(&root).is_ok());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn run_fails_when_a_case_does_not_match_its_expectation() {
        let root = setup("one-fail");
        write_case(&root, "a.json", "forbid"); // permit-all.cedar always permits
        assert!(run(&root).is_err());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn run_errors_on_an_empty_directory() {
        let root = setup("empty");
        assert!(run(&root).is_err());
        std::fs::remove_dir_all(&root).unwrap();
    }
}
