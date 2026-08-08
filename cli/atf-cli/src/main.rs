mod conformance;

use std::io::Read;
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
    /// Offline Operator subject and organization-role lifecycle commands.
    Operator {
        #[command(subcommand)]
        action: OperatorCommand,
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

#[derive(Subcommand)]
enum OperatorCommand {
    /// Bind one external issuer subject read from stdin to an internal Operator.
    ProvisionSubject {
        #[arg(long)]
        organization_id: String,
        #[arg(long)]
        operator_id: String,
        #[arg(long)]
        issuer_id: String,
        #[arg(long)]
        issuer_url: String,
        /// HUMAN or SERVICE.
        #[arg(long)]
        principal_kind: String,
        #[arg(long)]
        created_at: Timestamp,
        #[arg(long)]
        actor_id: String,
        #[arg(long)]
        occurred_at: Timestamp,
    },
    /// Grant one explicit organization role.
    GrantRole {
        #[arg(long)]
        organization_id: String,
        #[arg(long)]
        operator_id: String,
        /// org_admin, policy_author, approver, or auditor.
        #[arg(long)]
        role: String,
        #[arg(long)]
        actor_id: String,
        #[arg(long)]
        reason_code: String,
        #[arg(long)]
        occurred_at: Timestamp,
    },
    /// Revoke one exact organization role binding.
    RevokeRole {
        #[arg(long)]
        organization_id: String,
        #[arg(long)]
        operator_id: String,
        #[arg(long)]
        role: String,
        #[arg(long)]
        actor_id: String,
        #[arg(long)]
        reason_code: String,
        #[arg(long)]
        occurred_at: Timestamp,
    },
    /// Enable or disable one local Operator subject binding.
    SetStatus {
        #[arg(long)]
        operator_id: String,
        /// ACTIVE or DISABLED.
        #[arg(long)]
        status: String,
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
        Command::Operator { action } => run_operator(action).await,
    };

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run_operator(command: OperatorCommand) -> Result<()> {
    let database_url = std::env::var("DATABASE_URL")
        .context("DATABASE_URL is required for Operator lifecycle commands")?;
    let store = atf_store::Store::connect(&database_url)
        .await
        .context("connecting to the ATF durable-state database")?;
    let result = match command {
        OperatorCommand::ProvisionSubject {
            organization_id,
            operator_id,
            issuer_id,
            issuer_url,
            principal_kind,
            created_at,
            actor_id,
            occurred_at,
        } => {
            let subject = read_subject_from_stdin()?;
            let stored = store
                .provision_operator(
                    atf_store::OperatorRegistration {
                        operator_id,
                        issuer_id,
                        subject_fingerprint: atf_store::operator_subject_fingerprint(
                            &issuer_url,
                            &subject,
                        )?,
                        principal_kind: parse_operator_kind(&principal_kind)?,
                        audit_organization_id: organization_id,
                        created_at,
                    },
                    &actor_id,
                    occurred_at,
                )
                .await?;
            println!("operator_id: {}", stored.operator_id);
            print_mutation_evidence(stored.lifecycle_version, &stored.last_event_id);
            Ok(())
        }
        OperatorCommand::GrantRole {
            organization_id,
            operator_id,
            role,
            actor_id,
            reason_code,
            occurred_at,
        } => {
            let stored = store
                .grant_operator_role(
                    &operator_id,
                    &organization_id,
                    parse_operator_role(&role)?,
                    &actor_id,
                    &reason_code,
                    occurred_at,
                )
                .await?;
            println!("operator_id: {}", stored.operator_id);
            println!("role: {role}");
            print_mutation_evidence(stored.lifecycle_version, &stored.last_event_id);
            Ok(())
        }
        OperatorCommand::RevokeRole {
            organization_id,
            operator_id,
            role,
            actor_id,
            reason_code,
            occurred_at,
        } => {
            let stored = store
                .revoke_operator_role(
                    &operator_id,
                    &organization_id,
                    parse_operator_role(&role)?,
                    &actor_id,
                    &reason_code,
                    occurred_at,
                )
                .await?;
            println!("operator_id: {}", stored.operator_id);
            println!("role: {role}");
            print_mutation_evidence(stored.lifecycle_version, &stored.last_event_id);
            Ok(())
        }
        OperatorCommand::SetStatus {
            operator_id,
            status,
            actor_id,
            reason_code,
            occurred_at,
        } => {
            let stored = store
                .set_operator_status(
                    &operator_id,
                    parse_operator_status(&status)?,
                    &actor_id,
                    &reason_code,
                    occurred_at,
                )
                .await?;
            println!("operator_id: {}", stored.operator_id);
            print_mutation_evidence(stored.lifecycle_version, &stored.last_event_id);
            Ok(())
        }
    };
    store.close().await;
    result
}

fn read_subject_from_stdin() -> Result<String> {
    let mut subject = String::new();
    std::io::stdin()
        .take(513)
        .read_to_string(&mut subject)
        .context("reading external subject from stdin")?;
    while subject.ends_with('\r') || subject.ends_with('\n') {
        subject.pop();
    }
    if subject.contains('\r') || subject.contains('\n') {
        bail!("external subject stdin must contain exactly one line");
    }
    Ok(subject)
}

fn parse_operator_kind(value: &str) -> Result<atf_store::OperatorKind> {
    match value {
        "HUMAN" => Ok(atf_store::OperatorKind::Human),
        "SERVICE" => Ok(atf_store::OperatorKind::Service),
        _ => bail!("invalid Operator principal kind `{value}`"),
    }
}

fn parse_operator_status(value: &str) -> Result<atf_store::OperatorStatus> {
    match value {
        "ACTIVE" => Ok(atf_store::OperatorStatus::Active),
        "DISABLED" => Ok(atf_store::OperatorStatus::Disabled),
        _ => bail!("invalid Operator status `{value}`"),
    }
}

fn parse_operator_role(value: &str) -> Result<atf_store::OperatorRole> {
    match value {
        "org_admin" => Ok(atf_store::OperatorRole::OrgAdmin),
        "policy_author" => Ok(atf_store::OperatorRole::PolicyAuthor),
        "approver" => Ok(atf_store::OperatorRole::Approver),
        "auditor" => Ok(atf_store::OperatorRole::Auditor),
        _ => bail!("invalid Operator role `{value}`"),
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
