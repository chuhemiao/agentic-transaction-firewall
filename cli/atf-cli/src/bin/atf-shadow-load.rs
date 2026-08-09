use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use atf_core::{new_ulid, Amount, Timestamp};
use atf_decision::Decision;
use atf_identity::IdentityEnvelope;
use atf_intent::{Action, Mandate, Principal, Resource, Transaction, TransactionIntent};
use chrono::TimeDelta;
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use serde_json::{Map, Value};
use tokio::task::JoinSet;

const MAX_REQUESTS: u32 = 10_000;
const MAX_CONCURRENCY: u16 = 128;
const MAX_FILE_BYTES: u64 = 128 * 1024;

#[derive(Parser)]
#[command(
    name = "atf-shadow-load",
    about = "Bounded local Shadow HTTP client and load-evidence generator"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the Ed25519 public key for one local seed file.
    PublicKey {
        #[arg(long)]
        seed_file: PathBuf,
    },
    /// Verify the local TLS edge and durable Gateway readiness.
    Health {
        #[arg(long)]
        base_url: String,
        #[arg(long)]
        ca_cert: PathBuf,
    },
    /// Send unique signed Intents and emit a machine-readable measurement.
    Run {
        #[arg(long)]
        base_url: String,
        #[arg(long)]
        ca_cert: PathBuf,
        #[arg(long)]
        seed_file: PathBuf,
        #[arg(long, default_value_t = 1)]
        requests: u32,
        #[arg(long, default_value_t = 1)]
        concurrency: u16,
        #[arg(long, default_value_t = 0)]
        warmup_requests: u32,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        #[arg(long)]
        report: Option<PathBuf>,
        #[arg(long)]
        save_last_intent: Option<PathBuf>,
    },
}

#[derive(Clone)]
struct RequestContext {
    base_url: Arc<str>,
    client: reqwest::Client,
    signing_key: Arc<SigningKey>,
}

#[derive(Debug)]
struct Sample {
    intent_id: String,
    latency_milliseconds: u64,
    decision_hash: Option<String>,
    decision_outcome: Option<String>,
    error: Option<String>,
}

#[derive(Serialize)]
struct LoadReport {
    schema_version: u8,
    mode: &'static str,
    measured_at: Timestamp,
    requests: u32,
    concurrency: u16,
    successful_requests: usize,
    failed_requests: usize,
    elapsed_milliseconds: u64,
    throughput_per_second: String,
    p50_milliseconds: u64,
    p95_milliseconds: u64,
    p99_milliseconds: u64,
    decision_outcomes: BTreeMap<String, usize>,
    decision_hash: Option<String>,
    last_intent_id: Option<String>,
    prd_target_comparison: TargetComparison,
    residual_scope: [&'static str; 3],
}

#[derive(Serialize)]
struct TargetComparison {
    no_external_simulation_p95_target_milliseconds: u64,
    p95_target_met: bool,
    shadow_throughput_target_per_second: u64,
    throughput_target_met: bool,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match execute(Cli::parse()).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn execute(cli: Cli) -> Result<()> {
    match cli.command {
        Command::PublicKey { seed_file } => {
            println!(
                "{}",
                hex::encode(load_signing_key(&seed_file)?.verifying_key())
            );
            Ok(())
        }
        Command::Health { base_url, ca_cert } => {
            let base_url = validate_base_url(&base_url)?;
            let client = build_client(&ca_cert, Duration::from_secs(10))?;
            let response = client
                .get(format!("{base_url}/readyz"))
                .send()
                .await
                .context("requesting Gateway readiness")?;
            if !response.status().is_success() {
                bail!("Gateway readiness returned {}", response.status());
            }
            println!("readyz: ready");
            Ok(())
        }
        Command::Run {
            base_url,
            ca_cert,
            seed_file,
            requests,
            concurrency,
            warmup_requests,
            timeout_seconds,
            report,
            save_last_intent,
        } => {
            validate_run_limits(requests, concurrency, warmup_requests, timeout_seconds)?;
            let context = RequestContext {
                base_url: Arc::from(validate_base_url(&base_url)?),
                client: build_client(&ca_cert, Duration::from_secs(timeout_seconds))?,
                signing_key: Arc::new(load_signing_key(&seed_file)?),
            };

            for _ in 0..warmup_requests {
                let sample = send_one(&context).await;
                if let Some(error) = sample.error {
                    bail!("warmup request failed: {error}");
                }
            }

            let started = Instant::now();
            let samples = run_workers(context, requests, concurrency).await?;
            let elapsed_milliseconds = u64::try_from(started.elapsed().as_millis())
                .unwrap_or(u64::MAX)
                .max(1);
            let report_value = build_report(requests, concurrency, elapsed_milliseconds, &samples);
            let encoded = serde_json::to_vec_pretty(&report_value)
                .context("serializing local load evidence")?;
            println!("{}", String::from_utf8_lossy(&encoded));

            if let Some(path) = report {
                write_bounded_file(&path, &encoded)?;
            }
            if let Some(path) = save_last_intent {
                let intent_id = report_value
                    .last_intent_id
                    .as_deref()
                    .context("cannot save an Intent ID when every request failed")?;
                write_bounded_file(&path, format!("{intent_id}\n").as_bytes())?;
            }
            if report_value.failed_requests != 0 {
                let first = samples
                    .iter()
                    .find_map(|sample| sample.error.as_deref())
                    .unwrap_or("unknown request failure");
                bail!(
                    "{} Shadow requests failed; first: {first}",
                    report_value.failed_requests
                );
            }
            Ok(())
        }
    }
}

fn validate_run_limits(
    requests: u32,
    concurrency: u16,
    warmup_requests: u32,
    timeout_seconds: u64,
) -> Result<()> {
    if requests == 0 || requests > MAX_REQUESTS {
        bail!("requests must be between 1 and {MAX_REQUESTS}");
    }
    if concurrency == 0 || concurrency > MAX_CONCURRENCY || u32::from(concurrency) > requests {
        bail!("concurrency must be between 1 and min(requests, {MAX_CONCURRENCY})");
    }
    if warmup_requests > MAX_REQUESTS {
        bail!("warmup-requests must not exceed {MAX_REQUESTS}");
    }
    if !(1..=120).contains(&timeout_seconds) {
        bail!("timeout-seconds must be between 1 and 120");
    }
    Ok(())
}

fn validate_base_url(value: &str) -> Result<String> {
    let parsed = reqwest::Url::parse(value).context("base-url must be an absolute URL")?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        bail!("base-url must be an origin-only HTTPS URL without credentials or query data");
    }
    Ok(value.trim_end_matches('/').to_owned())
}

fn build_client(ca_cert: &Path, timeout: Duration) -> Result<reqwest::Client> {
    let pem = read_bounded_regular_file(ca_cert, MAX_FILE_BYTES)?;
    let certificate =
        reqwest::Certificate::from_pem(&pem).context("local edge CA is not a PEM certificate")?;
    reqwest::Client::builder()
        .https_only(true)
        .add_root_certificate(certificate)
        .timeout(timeout)
        .build()
        .context("building bounded Shadow HTTP client")
}

fn load_signing_key(path: &Path) -> Result<SigningKey> {
    let bytes = read_bounded_regular_file(path, 66)?;
    let value = std::str::from_utf8(&bytes)
        .context("seed file must be UTF-8")?
        .trim_end_matches(['\r', '\n']);
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("seed file must contain exactly 64 lowercase hexadecimal characters");
    }
    let decoded = hex::decode(value).context("decoding Ed25519 seed")?;
    let seed: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("Ed25519 seed must contain 32 bytes"))?;
    Ok(SigningKey::from_bytes(&seed))
}

fn read_bounded_regular_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspecting {}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > max_bytes {
        bail!(
            "{} must be a regular non-symlink file of at most {max_bytes} bytes",
            path.display()
        );
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    File::open(path)
        .with_context(|| format!("opening {}", path.display()))?
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {}", path.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        bail!("{} exceeds {max_bytes} bytes", path.display());
    }
    Ok(bytes)
}

fn write_bounded_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            bail!("{} must be a regular non-symlink file", path.display());
        }
    }
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    use std::io::Write as _;
    options
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?
        .write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))
}

async fn run_workers(
    context: RequestContext,
    requests: u32,
    concurrency: u16,
) -> Result<Vec<Sample>> {
    let next = Arc::new(AtomicU32::new(0));
    let mut workers = JoinSet::new();
    for _ in 0..concurrency {
        let context = context.clone();
        let next = Arc::clone(&next);
        workers.spawn(async move {
            let mut samples = Vec::new();
            loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                if index >= requests {
                    break;
                }
                samples.push(send_one(&context).await);
            }
            samples
        });
    }

    let mut samples = Vec::with_capacity(usize::try_from(requests).unwrap_or(0));
    while let Some(result) = workers.join_next().await {
        samples.extend(result.context("Shadow load worker panicked")?);
    }
    if samples.len() != usize::try_from(requests).unwrap_or(usize::MAX) {
        bail!("load workers returned an incomplete result set");
    }
    Ok(samples)
}

async fn send_one(context: &RequestContext) -> Sample {
    let intent = local_intent();
    let intent_id = intent.intent_id.clone();
    let envelope = local_envelope(&intent);
    let signature = context.signing_key.sign(&envelope.canonical_bytes());
    let started = Instant::now();
    let result = context
        .client
        .post(format!("{}/v1/intents", context.base_url))
        .header("content-type", "application/json")
        .header(
            "x-atf-identity-envelope",
            hex::encode(envelope.canonical_bytes()),
        )
        .header(
            "x-atf-identity-signature",
            hex::encode(signature.to_bytes()),
        )
        .json(&intent)
        .send()
        .await;

    let (decision_hash, decision_outcome, error) = match result {
        Err(error) => (None, None, Some(format!("transport: {error}"))),
        Ok(response) => {
            let status = response.status();
            match response.bytes().await {
                Err(error) => (None, None, Some(format!("response body: {error}"))),
                Ok(body) if !status.is_success() => {
                    let code = serde_json::from_slice::<Value>(&body)
                        .ok()
                        .and_then(|value| value.get("code")?.as_str().map(str::to_owned))
                        .unwrap_or_else(|| "UNKNOWN".into());
                    (None, None, Some(format!("HTTP {status} {code}")))
                }
                Ok(body) => match serde_json::from_slice::<Decision>(&body) {
                    Err(error) => (None, None, Some(format!("Decision JSON: {error}"))),
                    Ok(decision) => {
                        let verification = decision
                            .verify_hash()
                            .map_err(|error| error.to_string())
                            .and_then(|()| {
                                if decision.intent_id == intent_id {
                                    Ok(())
                                } else {
                                    Err("Decision intent_id does not match the request".into())
                                }
                            });
                        match verification {
                            Err(error) => {
                                (None, None, Some(format!("Decision verification: {error}")))
                            }
                            Ok(()) => (
                                Some(decision.decision_hash),
                                Some(format!("{:?}", decision.decision).to_uppercase()),
                                None,
                            ),
                        }
                    }
                },
            }
        }
    };

    Sample {
        intent_id,
        latency_milliseconds: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        decision_hash,
        decision_outcome,
        error,
    }
}

fn local_intent() -> TransactionIntent {
    let now = Timestamp::now_millis();
    TransactionIntent {
        spec_version: "1.0".into(),
        intent_id: new_ulid(),
        idempotency_key: format!("local-shadow-{}", new_ulid()),
        created_at: Timestamp::from_datetime(now.as_datetime() - TimeDelta::seconds(30)),
        expires_at: Timestamp::from_datetime(now.as_datetime() + TimeDelta::minutes(10)),
        principal: Principal {
            organization_id: "alpha-lab".into(),
            user_id: Some("local-user".into()),
            agent_id: "research-agent-01".into(),
            agent_version: Some("local-1".into()),
            strategy_id: None,
        },
        mandate: Mandate {
            mandate_id: "local-shadow-mandate".into(),
            task_id: Some("ds039-load".into()),
            purpose: "measure the local Shadow evaluation path".into(),
            budget_id: Some("local-shadow-budget".into()),
            human_authorized: true,
        },
        action: Action {
            category: "payment".into(),
            operation: "purchase_api_resource".into(),
        },
        resource: Resource {
            protocol: "x402".into(),
            venue: Some("local-fixture".into()),
            resource_id: format!("dataset-{}", new_ulid()),
            resource_type: Some("dataset".into()),
        },
        transaction: Transaction {
            network: "eip155:8453".into(),
            asset: "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913".into(),
            amount: Amount::from_str("1.00").expect("local fixture Amount is valid"),
            destination: Some("eip155:8453:0x1111111111111111111111111111111111111111".into()),
            contract: None,
            calldata_hash: None,
            max_fee: Some(Amount::from_str("0.01").expect("local fixture fee is valid")),
            slippage_bps: None,
            leverage: None,
        },
        context: Value::Object(Map::new()),
        metadata: Value::Object(Map::new()),
    }
}

fn local_envelope(intent: &TransactionIntent) -> IdentityEnvelope {
    let issued_at = Timestamp::now_millis();
    IdentityEnvelope {
        domain: "ATF_INTENT_V1".into(),
        organization_id: intent.principal.organization_id.clone(),
        agent_id: intent.principal.agent_id.clone(),
        key_id: "local-agent-key".into(),
        intent_hash: intent.canonical_hash(),
        issued_at,
        expires_at: Timestamp::from_datetime(issued_at.as_datetime() + TimeDelta::minutes(4)),
        nonce: format!("local-nonce-{}", new_ulid()),
        audience: "atf-local-gateway".into(),
        environment: "development".into(),
    }
}

fn build_report(
    requests: u32,
    concurrency: u16,
    elapsed_milliseconds: u64,
    samples: &[Sample],
) -> LoadReport {
    let successful = samples
        .iter()
        .filter(|sample| sample.error.is_none())
        .count();
    let mut latencies = samples
        .iter()
        .map(|sample| sample.latency_milliseconds)
        .collect::<Vec<_>>();
    latencies.sort_unstable();
    let mut decision_outcomes = BTreeMap::new();
    for outcome in samples
        .iter()
        .filter_map(|sample| sample.decision_outcome.as_ref())
    {
        *decision_outcomes.entry(outcome.clone()).or_insert(0) += 1;
    }
    let throughput_milli = u64::from(requests)
        .saturating_mul(1_000_000)
        .checked_div(elapsed_milliseconds)
        .unwrap_or(0);
    let p95 = percentile(&latencies, 95);
    LoadReport {
        schema_version: 1,
        mode: "DURABLE_SHADOW_HTTP_NO_EXTERNAL_SIMULATION",
        measured_at: Timestamp::now_millis(),
        requests,
        concurrency,
        successful_requests: successful,
        failed_requests: samples.len().saturating_sub(successful),
        elapsed_milliseconds,
        throughput_per_second: fixed_thousandths(throughput_milli),
        p50_milliseconds: percentile(&latencies, 50),
        p95_milliseconds: p95,
        p99_milliseconds: percentile(&latencies, 99),
        decision_outcomes,
        decision_hash: samples
            .iter()
            .find_map(|sample| sample.decision_hash.clone()),
        last_intent_id: samples
            .iter()
            .rev()
            .find(|sample| sample.error.is_none())
            .map(|sample| sample.intent_id.clone()),
        prd_target_comparison: TargetComparison {
            no_external_simulation_p95_target_milliseconds: 50,
            p95_target_met: p95 < 50,
            shadow_throughput_target_per_second: 100,
            throughput_target_met: throughput_milli >= 100_000,
        },
        residual_scope: [
            "single local Docker host; not production capacity evidence",
            "no external Simulation, Adapter, Approval, execution, or settlement path exists",
            "active-Agent cardinality, HA database, and shared-ingress quotas are not measured",
        ],
    }
}

fn percentile(sorted: &[u64], percent: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = sorted.len().saturating_mul(percent).saturating_add(99) / 100;
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

fn fixed_thousandths(value: u64) -> String {
    format!("{}.{:03}", value / 1_000, value % 1_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nearest_rank_percentiles_are_integer_and_deterministic() {
        let values = (1..=100).collect::<Vec<_>>();
        assert_eq!(percentile(&values, 50), 50);
        assert_eq!(percentile(&values, 95), 95);
        assert_eq!(percentile(&values, 99), 99);
        assert_eq!(percentile(&[7], 95), 7);
    }

    #[test]
    fn fixed_throughput_never_uses_binary_floating_point() {
        assert_eq!(fixed_thousandths(123_456), "123.456");
        assert_eq!(fixed_thousandths(7), "0.007");
    }

    #[test]
    fn load_limits_remain_bounded() {
        assert!(validate_run_limits(1, 1, 0, 1).is_ok());
        assert!(validate_run_limits(0, 1, 0, 1).is_err());
        assert!(validate_run_limits(MAX_REQUESTS + 1, 1, 0, 1).is_err());
        assert!(validate_run_limits(1, 2, 0, 1).is_err());
        assert!(validate_run_limits(1, 1, 0, 121).is_err());
    }

    #[test]
    fn base_url_rejects_cleartext_credentials_and_paths() {
        assert_eq!(
            validate_base_url("https://edge:8443/").unwrap(),
            "https://edge:8443"
        );
        assert!(validate_base_url("http://edge:8443/").is_err());
        assert!(validate_base_url("https://user:password@edge:8443/").is_err());
        assert!(validate_base_url("https://edge:8443/v1").is_err());
    }
}
