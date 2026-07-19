use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

/// ATF command-line interface (PRD §21). Only the two commands needed to
/// exercise today's Intent/Policy/Decision skeleton are implemented; the
/// rest of the MVP command list (`serve`, `shadow`, `policy validate`,
/// `policy test`, `audit show`, `replay`, `init`) waits on the crates that
/// would back them (see `docs/architecture.md`).
#[derive(Parser)]
#[command(name = "atf", version, about = "Agentic Transaction Firewall CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate a Transaction Intent JSON file against the schema and print its canonical hash.
    ValidateIntent {
        /// Path to a Transaction Intent JSON file.
        intent_path: PathBuf,
    },
    /// Evaluate a Transaction Intent against a Cedar policy bundle and print the resulting Decision.
    Evaluate {
        /// Path to a Transaction Intent JSON file.
        intent_path: PathBuf,
        /// Directory of `.cedar` policy files to load as one bundle.
        #[arg(long, default_value = "policies/examples")]
        policies: PathBuf,
    },
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::ValidateIntent { intent_path } => run_validate_intent(&intent_path),
        Command::Evaluate {
            intent_path,
            policies,
        } => run_evaluate(&intent_path, &policies),
    };

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn read_intent(path: &Path) -> Result<atf_intent::TransactionIntent> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading intent file {}", path.display()))?;
    atf_intent::validate(&raw).map_err(|e| anyhow::anyhow!("{e}"))
}

fn run_validate_intent(intent_path: &Path) -> Result<()> {
    let intent = read_intent(intent_path)?;
    println!("valid");
    println!("intent_id: {}", intent.intent_id);
    println!("canonical_hash: sha256:{}", intent.canonical_hash());
    Ok(())
}

fn run_evaluate(intent_path: &Path, policies_dir: &Path) -> Result<()> {
    let intent = read_intent(intent_path)?;
    let bundle = atf_policy::PolicyBundle::from_dir(policies_dir)
        .with_context(|| format!("loading policy bundle from {}", policies_dir.display()))?;
    let decision = atf_decision::decide(&bundle, &intent);
    println!("{}", serde_json::to_string_pretty(&decision)?);
    Ok(())
}
