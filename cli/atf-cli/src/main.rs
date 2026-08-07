mod conformance;

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use atf_core::Timestamp;
use atf_identity::{AgentRecord, AgentStatus, IdentityKeyRecord};
use clap::{Parser, Subcommand};

/// ATF command-line interface (PRD §21). Only the commands needed to
/// exercise today's Intent/Policy/Risk/Decision and offline Identity boundaries are implemented;
/// the rest of the MVP command list (`serve`, `shadow`, `policy validate`,
/// `audit show`, `replay`, `init`) waits on the crates that would back them
/// (see `docs/architecture.md`).
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
    /// Policy Bundle commands.
    Policy {
        #[command(subcommand)]
        action: PolicyCommand,
    },
    /// Offline Agent and Ed25519 public-key lifecycle commands.
    Identity {
        #[command(subcommand)]
        action: IdentityCommand,
    },
}

#[derive(Subcommand)]
enum PolicyCommand {
    /// Run the Policy Kernel conformance test cases and report pass/fail.
    Test {
        /// Directory of `*.json` conformance test cases.
        #[arg(long, default_value = "conformance/policy-tests")]
        dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum IdentityCommand {
    /// Provision one canonical Agent record.
    ProvisionAgent {
        /// Path to a canonical Agent record JSON file.
        record_path: PathBuf,
        #[arg(long)]
        actor_id: String,
        #[arg(long)]
        occurred_at: Timestamp,
    },
    /// Register one explicitly addressed Ed25519 public key.
    RegisterKey {
        #[arg(long)]
        organization_id: String,
        #[arg(long)]
        agent_id: String,
        #[arg(long)]
        key_id: String,
        /// Exactly 32 public bytes encoded as 64 lowercase hexadecimal characters.
        #[arg(long)]
        public_key_hex: String,
        #[arg(long)]
        activates_at: Timestamp,
        #[arg(long)]
        expires_at: Option<Timestamp>,
        #[arg(long)]
        actor_id: String,
        #[arg(long)]
        occurred_at: Timestamp,
    },
    /// Change an Agent lifecycle status.
    SetAgentStatus {
        #[arg(long)]
        organization_id: String,
        #[arg(long)]
        agent_id: String,
        /// ACTIVE, SHADOW_ONLY, PAUSED, REVOKED, or EXPIRED.
        #[arg(long)]
        status: String,
        #[arg(long)]
        actor_id: String,
        #[arg(long)]
        reason_code: String,
        #[arg(long)]
        occurred_at: Timestamp,
    },
    /// Irreversibly revoke one exact identity key.
    RevokeKey {
        #[arg(long)]
        organization_id: String,
        #[arg(long)]
        agent_id: String,
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        actor_id: String,
        #[arg(long)]
        reason_code: String,
        #[arg(long)]
        occurred_at: Timestamp,
    },
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::ValidateIntent { intent_path } => run_validate_intent(&intent_path),
        Command::Evaluate {
            intent_path,
            policies,
        } => run_evaluate(&intent_path, &policies),
        Command::Policy { action } => match action {
            PolicyCommand::Test { dir } => conformance::run(&dir),
        },
        Command::Identity { action } => run_identity(action).await,
    };

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run_identity(command: IdentityCommand) -> Result<()> {
    let database_url = std::env::var("DATABASE_URL")
        .context("DATABASE_URL is required for identity lifecycle commands")?;
    let store = atf_store::Store::connect(&database_url)
        .await
        .context("connecting to the ATF durable-state database")?;

    let result = match command {
        IdentityCommand::ProvisionAgent {
            record_path,
            actor_id,
            occurred_at,
        } => {
            let raw = std::fs::read_to_string(&record_path)
                .with_context(|| format!("reading Agent record {}", record_path.display()))?;
            let record: AgentRecord = serde_json::from_str(&raw)
                .with_context(|| format!("decoding Agent record {}", record_path.display()))?;
            let stored = store
                .provision_agent(record, &actor_id, occurred_at)
                .await?;
            println!("agent_id: {}", stored.record.agent_id);
            print_mutation_evidence(stored.lifecycle_version, &stored.last_event_id);
            Ok(())
        }
        IdentityCommand::RegisterKey {
            organization_id,
            agent_id,
            key_id,
            public_key_hex,
            activates_at,
            expires_at,
            actor_id,
            occurred_at,
        } => {
            let public_key = decode_public_key_hex(&public_key_hex)?;
            let record = IdentityKeyRecord::from_public_key_bytes(
                agent_id,
                key_id,
                &public_key,
                activates_at,
                expires_at,
                None,
            )?;
            let stored = store
                .register_identity_key(&organization_id, record, &actor_id, occurred_at)
                .await?;
            println!("key_id: {}", stored.record.key_id);
            print_mutation_evidence(stored.lifecycle_version, &stored.last_event_id);
            Ok(())
        }
        IdentityCommand::SetAgentStatus {
            organization_id,
            agent_id,
            status,
            actor_id,
            reason_code,
            occurred_at,
        } => {
            let stored = store
                .set_agent_status(
                    &organization_id,
                    &agent_id,
                    parse_agent_status(&status)?,
                    &actor_id,
                    &reason_code,
                    occurred_at,
                )
                .await?;
            println!("agent_id: {}", stored.record.agent_id);
            print_mutation_evidence(stored.lifecycle_version, &stored.last_event_id);
            Ok(())
        }
        IdentityCommand::RevokeKey {
            organization_id,
            agent_id,
            key_id,
            actor_id,
            reason_code,
            occurred_at,
        } => {
            let stored = store
                .revoke_identity_key(
                    &organization_id,
                    &agent_id,
                    &key_id,
                    &actor_id,
                    &reason_code,
                    occurred_at,
                )
                .await?;
            println!("key_id: {}", stored.record.key_id);
            print_mutation_evidence(stored.lifecycle_version, &stored.last_event_id);
            Ok(())
        }
    };
    store.close().await;
    result
}

fn print_mutation_evidence(lifecycle_version: i64, event_id: &str) {
    println!("lifecycle_version: {lifecycle_version}");
    println!("audit_event_id: {event_id}");
}

fn parse_agent_status(value: &str) -> Result<AgentStatus> {
    match value {
        "ACTIVE" => Ok(AgentStatus::Active),
        "SHADOW_ONLY" => Ok(AgentStatus::ShadowOnly),
        "PAUSED" => Ok(AgentStatus::Paused),
        "REVOKED" => Ok(AgentStatus::Revoked),
        "EXPIRED" => Ok(AgentStatus::Expired),
        _ => bail!("invalid Agent status `{value}`"),
    }
}

fn decode_public_key_hex(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("public key must be exactly 64 lowercase hexadecimal characters");
    }
    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .context("decoding Ed25519 public key")?;
    }
    Ok(bytes)
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

    let policy_result = bundle.evaluate(&intent);
    // Only score Risk if Policy didn't already deny — PRD §10.1.2: a
    // forbidden request terminates the merge before Risk is consulted.
    let risk_findings = match &policy_result {
        Ok(outcome) if outcome.decision == atf_policy::PolicyDecision::Permit => {
            atf_risk::evaluate(&intent, &atf_risk::RiskConfig::default())
        }
        _ => Vec::new(),
    };

    let decision = atf_decision::decide(&intent, policy_result, &risk_findings);
    println!("{}", serde_json::to_string_pretty(&decision)?);
    Ok(())
}
