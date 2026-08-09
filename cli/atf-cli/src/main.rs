mod conformance;

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use atf_core::{
    sha256_hex, DailySpendHistory, DailySpendQuery, DestinationNormalization,
    DuplicatePurchaseHistory, DuplicatePurchaseQuery, EvaluationContext, EvaluationContextInput,
    EvidenceTrustPolicyReference, ExternalSnapshotReference, FirstDestinationHistory,
    FirstDestinationQuery, RepositorySnapshot, RequestFrequencyHistory, RequestFrequencyQuery,
    RiskHistorySnapshot, SimulationReference, Timestamp, VersionedArtifactReference,
};
use atf_identity::{AgentRecord, AgentStatus, IdentityKeyRecord};
use clap::{Parser, Subcommand};

/// ATF command-line interface (PRD §21). Only the commands needed to
/// exercise today's Intent/Policy/Risk/Decision, Original Replay, and offline Identity boundaries
/// are implemented; the rest of the MVP command list (`serve`, `shadow`, `policy validate`,
/// `audit show`, `init`) waits on the crates that would back them
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
    /// Immutable Risk Rule Set artifact commands.
    Risk {
        #[command(subcommand)]
        action: RiskCommand,
    },
    /// Deterministic Replay commands.
    Replay {
        #[command(subcommand)]
        action: ReplayCommand,
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
enum RiskCommand {
    /// Validate and immutably install one Risk Rule Set for replay.
    Install {
        rule_set_path: PathBuf,
        #[arg(long)]
        organization_id: String,
        #[arg(long)]
        environment: String,
        #[arg(long)]
        actor_id: String,
        #[arg(long)]
        occurred_at: Timestamp,
    },
}

#[derive(Subcommand)]
enum ReplayCommand {
    /// Reproduce an authoritative Decision from its exact immutable inputs.
    Original {
        #[arg(long)]
        organization_id: String,
        #[arg(long)]
        intent_id: String,
        #[arg(long)]
        actor_id: String,
        #[arg(long)]
        occurred_at: Timestamp,
        /// Caller-supplied replay correlation ID; defaults to a fresh ULID.
        #[arg(long)]
        replay_id: Option<String>,
    },
    /// Re-evaluate an original snapshot with explicitly selected artifacts.
    Counterfactual {
        #[arg(long)]
        organization_id: String,
        #[arg(long)]
        intent_id: String,
        #[arg(long)]
        actor_id: String,
        #[arg(long)]
        occurred_at: Timestamp,
        #[arg(long)]
        policy_bundle_id: String,
        #[arg(long)]
        policy_version: String,
        #[arg(long)]
        policy_bundle_hash: String,
        #[arg(long)]
        risk_engine_version: String,
        #[arg(long)]
        risk_rule_set_version: String,
        #[arg(long)]
        risk_rule_set_hash: String,
        /// Caller-supplied replay correlation ID; defaults to a fresh ULID.
        #[arg(long)]
        replay_id: Option<String>,
        /// New non-authoritative Evaluation ID; defaults to a fresh ULID.
        #[arg(long)]
        evaluation_id: Option<String>,
        /// New non-authoritative Decision ID; defaults to a fresh ULID.
        #[arg(long)]
        decision_id: Option<String>,
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
        Command::Risk { action } => run_risk(action).await,
        Command::Replay { action } => run_replay(action).await,
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

async fn run_risk(command: RiskCommand) -> Result<()> {
    let database_url = std::env::var("DATABASE_URL")
        .context("DATABASE_URL is required for Risk Rule Set commands")?;
    let store = atf_store::Store::connect(&database_url)
        .await
        .context("connecting to the ATF durable-state database")?;
    let RiskCommand::Install {
        rule_set_path,
        organization_id,
        environment,
        actor_id,
        occurred_at,
    } = command;
    let rule_set = atf_risk::RiskRuleSet::from_file(&rule_set_path)
        .with_context(|| format!("validating Risk Rule Set {}", rule_set_path.display()))?;
    let stored = store
        .install_risk_rule_set(
            &organization_id,
            &environment,
            &rule_set,
            &actor_id,
            occurred_at,
        )
        .await
        .context("installing immutable Risk Rule Set")?;
    println!("engine_version: {}", stored.engine_version);
    println!("rule_set_version: {}", stored.rule_set_version);
    println!("rule_set_hash: {}", stored.rule_set_hash);
    println!("artifact_hash: {}", stored.artifact_hash);
    println!("audit_event_id: {}", stored.installed_event_id);
    store.close().await;
    Ok(())
}

async fn run_replay(command: ReplayCommand) -> Result<()> {
    let database_url =
        std::env::var("DATABASE_URL").context("DATABASE_URL is required for Replay commands")?;
    let store = atf_store::Store::connect(&database_url)
        .await
        .context("connecting to the ATF durable-state database")?;
    match command {
        ReplayCommand::Original {
            organization_id,
            intent_id,
            actor_id,
            occurred_at,
            replay_id,
        } => {
            let result = store
                .replay_original(atf_store::OriginalReplayRequest {
                    replay_id: replay_id.unwrap_or_else(atf_core::new_ulid),
                    organization_id,
                    intent_id,
                    actor_id,
                    occurred_at,
                })
                .await
                .map_err(|error| anyhow::anyhow!("{}: {error}", error.code()))?;
            println!("replay_id: {}", result.replay_id);
            println!("original_evaluation_id: {}", result.original_evaluation_id);
            println!("original_decision_id: {}", result.original_decision_id);
            println!("original_decision_hash: {}", result.original_decision_hash);
            println!("replayed_decision_hash: {}", result.replayed_decision_hash);
            println!("matched: {}", result.matched);
            println!("audit_event_id: {}", result.audit_event.event.event_id);
        }
        ReplayCommand::Counterfactual {
            organization_id,
            intent_id,
            actor_id,
            occurred_at,
            policy_bundle_id,
            policy_version,
            policy_bundle_hash,
            risk_engine_version,
            risk_rule_set_version,
            risk_rule_set_hash,
            replay_id,
            evaluation_id,
            decision_id,
        } => {
            let result = store
                .replay_counterfactual(atf_store::CounterfactualReplayRequest {
                    replay_id: replay_id.unwrap_or_else(atf_core::new_ulid),
                    organization_id,
                    intent_id,
                    counterfactual_evaluation_id: evaluation_id.unwrap_or_else(atf_core::new_ulid),
                    counterfactual_decision_id: decision_id.unwrap_or_else(atf_core::new_ulid),
                    selected_policy: atf_store::PolicyReplaySelection {
                        bundle_id: policy_bundle_id,
                        policy_version,
                        bundle_hash: policy_bundle_hash,
                    },
                    selected_risk: atf_store::RiskReplaySelection {
                        engine_version: risk_engine_version,
                        rule_set_version: risk_rule_set_version,
                        rule_set_hash: risk_rule_set_hash,
                    },
                    actor_id,
                    occurred_at,
                })
                .await
                .map_err(|error| anyhow::anyhow!("{}: {error}", error.code()))?;
            println!("replay_id: {}", result.replay_id);
            println!("authoritative: {}", result.authoritative);
            println!("original_evaluation_id: {}", result.original_evaluation_id);
            println!("original_decision_id: {}", result.original_decision_id);
            println!("original_decision_hash: {}", result.original_decision_hash);
            println!(
                "original_outcome: {}",
                decision_kind_name(result.original_outcome)
            );
            println!(
                "counterfactual_evaluation_id: {}",
                result.evaluation.evaluation_id
            );
            println!("counterfactual_evaluation_hash: {}", result.evaluation_hash);
            println!(
                "counterfactual_decision_id: {}",
                result.decision.decision_id
            );
            println!("counterfactual_decision_hash: {}", result.decision_hash);
            println!(
                "counterfactual_outcome: {}",
                decision_kind_name(result.decision.decision)
            );
            println!("outcome_changed: {}", result.outcome_changed);
            println!("policy_bundle_id: {}", result.selected_policy.bundle_id);
            println!("policy_version: {}", result.selected_policy.policy_version);
            println!("policy_bundle_hash: {}", result.selected_policy.bundle_hash);
            println!(
                "risk_engine_version: {}",
                result.selected_risk.engine_version
            );
            println!(
                "risk_rule_set_version: {}",
                result.selected_risk.rule_set_version
            );
            println!("risk_rule_set_hash: {}", result.selected_risk.rule_set_hash);
            println!("audit_event_id: {}", result.audit_event.event.event_id);
        }
    }
    store.close().await;
    Ok(())
}

const fn decision_kind_name(kind: atf_core::DecisionKind) -> &'static str {
    match kind {
        atf_core::DecisionKind::Permit => "PERMIT",
        atf_core::DecisionKind::Review => "REVIEW",
        atf_core::DecisionKind::Deny => "DENY",
        atf_core::DecisionKind::Error => "ERROR",
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

    let risk_rule_set =
        atf_risk::RiskRuleSet::from_file(risk_rule_set_path).with_context(|| {
            format!(
                "loading Risk Rule Set from {}",
                risk_rule_set_path.display()
            )
        })?;
    let (evaluation_context, history) =
        local_evaluation_context(&intent, &bundle, &risk_rule_set, evaluated_at)?;
    let policy_result = bundle.evaluate(&intent, &evaluation_context);
    // Only score Risk if Policy didn't already deny — PRD §10.1.2: a
    // forbidden request terminates the merge before Risk is consulted.
    let risk_result = match &policy_result {
        Ok(outcome) if outcome.decision == atf_policy::PolicyDecision::Permit => Some(
            atf_risk::evaluate_context(&intent, &risk_rule_set, &evaluation_context, &history),
        ),
        _ => None,
    };

    let policy_input = match &policy_result {
        Ok(outcome) => atf_decision::PolicyDecisionInput::Evaluated(outcome),
        Err(_) => atf_decision::PolicyDecisionInput::Error {
            error_code: "POLICY_EVALUATION_ERROR",
        },
    };
    let risk_input = match (&risk_result, &policy_result) {
        (Some(Ok(evaluation)), _) => atf_decision::RiskDecisionInput::Evaluated(evaluation),
        (Some(Err(error)), _) => atf_decision::RiskDecisionInput::Error {
            error_code: error.code(),
        },
        (None, Ok(_)) => atf_decision::RiskDecisionInput::NotRun {
            reason_code: "POLICY_FORBID",
        },
        (None, Err(_)) => atf_decision::RiskDecisionInput::NotRun {
            reason_code: "POLICY_ERROR",
        },
    };
    let decision = atf_decision::decide(atf_decision::DecisionInput {
        decision_id: atf_core::new_ulid(),
        intent: &intent,
        evaluation_context: &evaluation_context,
        policy: policy_input,
        risk: risk_input,
    })
    .context("binding canonical Decision")?;
    println!("{}", serde_json::to_string_pretty(&decision)?);
    Ok(())
}

fn local_evaluation_context(
    intent: &atf_intent::TransactionIntent,
    bundle: &atf_policy::PolicyBundle,
    risk_rule_set: &atf_risk::RiskRuleSet,
    evaluated_at: Timestamp,
) -> Result<(EvaluationContext, RiskHistorySnapshot)> {
    let profile = atf_intent::validate_profile(intent)
        .map_err(|error| anyhow::anyhow!("resolving Intent Profile: {error}"))?;
    let repository = RepositorySnapshot::new(
        format!("audit-chain:{}:1", intent.principal.organization_id),
        1,
        sha256_hex(format!("cli-history:{}", intent.intent_id).as_bytes()),
    )?;
    let context = EvaluationContext::new(EvaluationContextInput {
        evaluation_id: format!("cli-evaluation-{}", intent.intent_id),
        intent_id: intent.intent_id.clone(),
        intent_hash: intent.canonical_hash(),
        evaluation_time: evaluated_at,
        environment: bundle.environment().into(),
        profile_id: profile.id().into(),
        profile_version: profile.version().into(),
        policy: VersionedArtifactReference::available(
            bundle.bundle_id(),
            bundle.policy_version(),
            bundle.bundle_hash(),
        )?,
        risk: VersionedArtifactReference::available(
            risk_rule_set.engine_version(),
            risk_rule_set.version(),
            risk_rule_set.rule_set_hash(),
        )?,
        context_snapshot_id: format!("cli-context-{}", intent.intent_id),
        agent_context: intent.context.clone(),
        evidence: Vec::new(),
        evidence_trust_policy: EvidenceTrustPolicyReference::not_configured(
            "TRUST_POLICY_NOT_CONFIGURED",
        )?,
        history: repository.clone(),
        market_data: ExternalSnapshotReference::unavailable("MARKET_DATA_SNAPSHOT_UNAVAILABLE")?,
        simulation: SimulationReference::not_run("SIMULATOR_NOT_IMPLEMENTED")?,
    })?;
    let duplicate_purchase = risk_rule_set.duplicate_purchase_enabled().then(|| {
        DuplicatePurchaseHistory::new(
            DuplicatePurchaseQuery::new(
                &intent.principal.organization_id,
                &intent.principal.agent_id,
                &intent.resource.resource_id,
                &intent.intent_id,
                evaluated_at,
                risk_rule_set.duplicate_purchase_window_seconds(),
                risk_rule_set.duplicate_purchase_accounting_boundary(),
            )?,
            None,
        )
    });
    let duplicate_purchase = match duplicate_purchase {
        Some(history) => Some(history?),
        None => None,
    };
    let daily_cumulative_spend = risk_rule_set.daily_spend_enabled().then(|| {
        DailySpendHistory::new(
            DailySpendQuery::new(
                &intent.principal.organization_id,
                &intent.principal.agent_id,
                &intent.intent_id,
                risk_rule_set
                    .daily_spend_valuation_asset()
                    .expect("validated enabled daily-spend rule has an asset"),
                evaluated_at,
                risk_rule_set
                    .daily_spend_window_seconds()
                    .expect("validated enabled daily-spend rule has a window"),
                risk_rule_set
                    .daily_spend_accounting_boundary()
                    .expect("validated enabled daily-spend rule has a boundary"),
            )?,
            Vec::new(),
            0,
        )
    });
    let daily_cumulative_spend = match daily_cumulative_spend {
        Some(history) => Some(history?),
        None => None,
    };
    let first_destination = risk_rule_set.first_destination_enabled().then(|| {
        let destination = match atf_intent::normalize_destination(intent) {
            Ok(destination) => DestinationNormalization::available(destination.value())?,
            Err(error) => DestinationNormalization::unavailable(error.code())?,
        };
        FirstDestinationHistory::new(
            FirstDestinationQuery::new(
                &intent.principal.organization_id,
                &intent.intent_id,
                profile.id(),
                profile.version(),
                risk_rule_set
                    .first_destination_normalizer_id()
                    .expect("validated enabled first-destination rule has a normalizer ID"),
                risk_rule_set
                    .first_destination_normalizer_version()
                    .expect("validated enabled first-destination rule has a normalizer version"),
                destination,
                evaluated_at,
                risk_rule_set
                    .first_destination_accounting_boundary()
                    .expect("validated enabled first-destination rule has a boundary"),
            )?,
            None,
        )
    });
    let first_destination = match first_destination {
        Some(history) => Some(history?),
        None => None,
    };
    let request_frequency = risk_rule_set.request_frequency_enabled().then(|| {
        RequestFrequencyHistory::new(
            RequestFrequencyQuery::new(
                &intent.principal.organization_id,
                &intent.principal.agent_id,
                &intent.intent_id,
                profile.id(),
                profile.version(),
                &intent.action.category,
                &intent.action.operation,
                risk_rule_set
                    .request_frequency_subject()
                    .expect("validated enabled request-frequency rule has a subject"),
                risk_rule_set
                    .request_frequency_action_scope()
                    .expect("validated enabled request-frequency rule has an action scope"),
                evaluated_at,
                risk_rule_set
                    .request_frequency_window_seconds()
                    .expect("validated enabled request-frequency rule has a window"),
                risk_rule_set
                    .request_frequency_max_requests()
                    .expect("validated enabled request-frequency rule has a threshold"),
                risk_rule_set
                    .request_frequency_accounting_boundary()
                    .expect("validated enabled request-frequency rule has a boundary"),
            )?,
            1,
            0,
        )
    });
    let request_frequency = match request_frequency {
        Some(history) => Some(history?),
        None => None,
    };
    Ok((
        context,
        RiskHistorySnapshot::with_request_frequency(
            repository,
            duplicate_purchase,
            daily_cumulative_spend,
            first_destination,
            request_frequency,
        )?,
    ))
}
