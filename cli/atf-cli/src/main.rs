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
        /// Deployment environment that must match the Policy Bundle scope.
        #[arg(long, default_value = "development")]
        environment: String,
        /// Explicit evaluation time; defaults to the current time.
        #[arg(long)]
        evaluated_at: Option<Timestamp>,
        /// Closed versioned Risk Rule Set artifact.
        #[arg(long, default_value = "risk-rules/default.json")]
        risk_rule_set: PathBuf,
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
    /// Verify and immutably install one signed Policy Bundle.
    Install {
        /// Directory containing manifest.json and its exact bound files.
        bundle_dir: PathBuf,
        #[arg(long)]
        organization_id: String,
        #[arg(long)]
        environment: String,
        /// Detached proof; defaults to <bundle-dir>/signature.json.
        #[arg(long)]
        signature: Option<PathBuf>,
        /// File containing exactly one lowercase-hex Ed25519 public key.
        #[arg(long)]
        publisher_public_key: PathBuf,
        #[arg(long)]
        actor_id: String,
        #[arg(long)]
        occurred_at: Timestamp,
    },
    /// Atomically select an installed signed version as active.
    Activate {
        #[arg(long)]
        organization_id: String,
        #[arg(long)]
        environment: String,
        #[arg(long)]
        bundle_id: String,
        #[arg(long)]
        policy_version: String,
        #[arg(long)]
        actor_id: String,
        #[arg(long)]
        occurred_at: Timestamp,
    },
    /// Atomically return to the immediately prior immutable signed version.
    Rollback {
        #[arg(long)]
        organization_id: String,
        #[arg(long)]
        environment: String,
        #[arg(long)]
        bundle_id: String,
        #[arg(long)]
        actor_id: String,
        #[arg(long)]
        occurred_at: Timestamp,
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
            environment,
            evaluated_at,
            risk_rule_set,
        } => run_evaluate(
            &intent_path,
            &policies,
            &environment,
            evaluated_at,
            &risk_rule_set,
        ),
        Command::Policy { action } => run_policy(action).await,
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

async fn run_policy(command: PolicyCommand) -> Result<()> {
    if let PolicyCommand::Test { dir } = &command {
        return conformance::run(dir);
    }
    let database_url = std::env::var("DATABASE_URL")
        .context("DATABASE_URL is required for Policy lifecycle commands")?;
    let store = atf_store::Store::connect(&database_url)
        .await
        .context("connecting to the ATF durable-state database")?;
    let result = match command {
        PolicyCommand::Test { .. } => unreachable!("handled before database connection"),
        PolicyCommand::Install {
            bundle_dir,
            organization_id,
            environment,
            signature,
            publisher_public_key,
            actor_id,
            occurred_at,
        } => {
            let bundle = atf_policy::PolicyBundle::from_dir_for_install(
                &bundle_dir,
                &organization_id,
                &environment,
            )
            .with_context(|| format!("validating Policy Bundle {}", bundle_dir.display()))?;
            let signature_path = signature.unwrap_or_else(|| bundle_dir.join("signature.json"));
            let signature = atf_policy::PolicyBundleSignature::from_file(&signature_path)
                .with_context(|| {
                    format!("reading Policy Bundle proof {}", signature_path.display())
                })?;
            let public_key = read_public_key_file(&publisher_public_key)?;
            let stored = store
                .install_policy_bundle(&bundle, &signature, &public_key, &actor_id, occurred_at)
                .await?;
            println!("bundle_id: {}", stored.bundle_id);
            println!("policy_version: {}", stored.policy_version);
            println!("bundle_hash: {}", stored.bundle_hash);
            println!("publisher_key_id: {}", stored.publisher_key_id);
            println!("audit_event_id: {}", stored.installed_event_id);
            Ok(())
        }
        PolicyCommand::Activate {
            organization_id,
            environment,
            bundle_id,
            policy_version,
            actor_id,
            occurred_at,
        } => {
            let active = store
                .activate_policy_bundle(
                    &organization_id,
                    &environment,
                    &bundle_id,
                    &policy_version,
                    &actor_id,
                    occurred_at,
                )
                .await?;
            print_active_policy(&active);
            Ok(())
        }
        PolicyCommand::Rollback {
            organization_id,
            environment,
            bundle_id,
            actor_id,
            occurred_at,
        } => {
            let active = store
                .rollback_policy_bundle(
                    &organization_id,
                    &environment,
                    &bundle_id,
                    &actor_id,
                    occurred_at,
                )
                .await?;
            print_active_policy(&active);
            Ok(())
        }
    };
    store.close().await;
    result
}

fn print_active_policy(active: &atf_store::ActivePolicyBundle) {
    println!("bundle_id: {}", active.bundle.bundle_id());
    println!("policy_version: {}", active.bundle.policy_version());
    println!("bundle_hash: {}", active.bundle.bundle_hash());
    println!("lifecycle_version: {}", active.lifecycle_version);
    println!("audit_event_id: {}", active.last_event_id);
}

fn read_public_key_file(path: &Path) -> Result<[u8; 32]> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspecting publisher public key {}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 66 {
        bail!("publisher public-key path must be a regular file of at most 66 bytes");
    }
    let file = std::fs::File::open(path)
        .with_context(|| format!("opening publisher public key {}", path.display()))?;
    let mut value = String::new();
    file.take(129)
        .read_to_string(&mut value)
        .with_context(|| format!("reading publisher public key {}", path.display()))?;
    while value.ends_with('\r') || value.ends_with('\n') {
        value.pop();
    }
    if value.contains('\r') || value.contains('\n') {
        bail!("publisher public-key file must contain exactly one line");
    }
    decode_public_key_hex(&value)
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

fn run_evaluate(
    intent_path: &Path,
    policies_dir: &Path,
    environment: &str,
    evaluated_at: Option<Timestamp>,
    risk_rule_set_path: &Path,
) -> Result<()> {
    let intent = read_intent(intent_path)?;
    let evaluated_at = evaluated_at.unwrap_or_else(Timestamp::now);
    let bundle = atf_policy::PolicyBundle::from_dir(
        policies_dir,
        &atf_policy::PolicyBundleLoadContext {
            organization_id: intent.principal.organization_id.clone(),
            environment: environment.to_owned(),
            evaluated_at,
        },
    )
    .with_context(|| format!("loading policy bundle from {}", policies_dir.display()))?;

    let policy_result = bundle.evaluate_at(&intent, evaluated_at);
    // Only score Risk if Policy didn't already deny — PRD §10.1.2: a
    // forbidden request terminates the merge before Risk is consulted.
    let risk_rule_set =
        atf_risk::RiskRuleSet::from_file(risk_rule_set_path).with_context(|| {
            format!(
                "loading Risk Rule Set from {}",
                risk_rule_set_path.display()
            )
        })?;
    let risk_findings = match &policy_result {
        Ok(outcome) if outcome.decision == atf_policy::PolicyDecision::Permit => {
            atf_risk::evaluate_at(&intent, &risk_rule_set, evaluated_at).findings
        }
        _ => Vec::new(),
    };

    let decision = atf_decision::decide(&intent, policy_result, &risk_findings);
    println!("{}", serde_json::to_string_pretty(&decision)?);
    Ok(())
}
