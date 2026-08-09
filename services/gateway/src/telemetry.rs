use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use atf_core::{DecisionKind, EvidenceFreshness};
use atf_store::DurableReplayCounts;
use axum::extract::MatchedPath;
use axum::http::{Method, Request, StatusCode};

const HISTOGRAM_BUCKETS_MICROS: [u64; 10] = [
    1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000, 1_000_000,
];
const HISTOGRAM_BUCKET_LABELS: [&str; 10] = [
    "0.001", "0.0025", "0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1",
];

/// Process-local Gateway telemetry with a deliberately closed label domain.
///
/// Callers cannot submit arbitrary labels: every dimension is represented by
/// an internal enum and raw request paths, tenant IDs, Intent IDs, credentials,
/// payloads, signatures, and error text are never retained.
#[derive(Clone, Default)]
pub(crate) struct GatewayTelemetry(Arc<Mutex<Metrics>>);

#[derive(Default)]
struct Metrics {
    http: BTreeMap<HttpKey, RequestMetric>,
    decisions: BTreeMap<DecisionLabel, u64>,
    policy_duration: BTreeMap<PolicyOutcomeLabel, Histogram>,
    policy_matches: BTreeMap<PolicyOutcomeLabel, u64>,
    risk_duration: BTreeMap<RiskOutcomeLabel, Histogram>,
    risk_findings: BTreeMap<SeverityLabel, u64>,
    idempotency: BTreeMap<IdempotencyOutcome, u64>,
    freshness: BTreeMap<FreshnessLabel, u64>,
    audit_failures: BTreeMap<AuditOperation, u64>,
    dependency_failures: BTreeMap<DependencyFailure, u64>,
    request_rejections: BTreeMap<RequestRejection, u64>,
}

#[derive(Default)]
struct RequestMetric {
    count: u64,
    duration: Histogram,
}

#[derive(Default)]
struct Histogram {
    count: u64,
    sum_micros: u64,
    buckets: [u64; HISTOGRAM_BUCKETS_MICROS.len()],
}

impl Histogram {
    fn observe(&mut self, duration: Duration) {
        let micros = u64::try_from(duration.as_micros()).unwrap_or(u64::MAX);
        self.count = self.count.saturating_add(1);
        self.sum_micros = self.sum_micros.saturating_add(micros);
        for (upper_bound, count) in HISTOGRAM_BUCKETS_MICROS.iter().zip(self.buckets.iter_mut()) {
            if micros <= *upper_bound {
                *count = count.saturating_add(1);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct HttpKey {
    method: MethodLabel,
    route: RouteLabel,
    status: StatusClass,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum MethodLabel {
    Get,
    Post,
    Other,
}

impl MethodLabel {
    fn from_method(method: &Method) -> Self {
        match *method {
            Method::GET => Self::Get,
            Method::POST => Self::Post,
            _ => Self::Other,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Other => "OTHER",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum RouteLabel {
    Health,
    Ready,
    Metrics,
    CreateIntent,
    ReadDecision,
    QueryAudit,
    QueryIntentAudit,
    ActivatePolicy,
    RollbackPolicy,
    Unmatched,
}

impl RouteLabel {
    fn from_request(request: &Request<axum::body::Body>) -> Self {
        request
            .extensions()
            .get::<MatchedPath>()
            .map(MatchedPath::as_str)
            .map_or(Self::Unmatched, Self::from_matched_path)
    }

    fn from_matched_path(path: &str) -> Self {
        match path {
            "/healthz" => Self::Health,
            "/readyz" => Self::Ready,
            "/metrics" => Self::Metrics,
            "/v1/intents" => Self::CreateIntent,
            "/v1/intents/{intent_id}/decision" => Self::ReadDecision,
            "/v1/audit/events" => Self::QueryAudit,
            "/v1/audit/intents/{intent_id}" => Self::QueryIntentAudit,
            "/v1/policy-bundles/{bundle_id}/activate" => Self::ActivatePolicy,
            "/v1/policy-bundles/{bundle_id}/rollback" => Self::RollbackPolicy,
            _ => Self::Unmatched,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Health => "/healthz",
            Self::Ready => "/readyz",
            Self::Metrics => "/metrics",
            Self::CreateIntent => "/v1/intents",
            Self::ReadDecision => "/v1/intents/{intent_id}/decision",
            Self::QueryAudit => "/v1/audit/events",
            Self::QueryIntentAudit => "/v1/audit/intents/{intent_id}",
            Self::ActivatePolicy => "/v1/policy-bundles/{bundle_id}/activate",
            Self::RollbackPolicy => "/v1/policy-bundles/{bundle_id}/rollback",
            Self::Unmatched => "UNMATCHED",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum StatusClass {
    Informational,
    Success,
    Redirection,
    ClientError,
    ServerError,
}

impl StatusClass {
    fn from_status(status: StatusCode) -> Self {
        if status.is_informational() {
            Self::Informational
        } else if status.is_success() {
            Self::Success
        } else if status.is_redirection() {
            Self::Redirection
        } else if status.is_client_error() {
            Self::ClientError
        } else {
            Self::ServerError
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "1xx",
            Self::Success => "2xx",
            Self::Redirection => "3xx",
            Self::ClientError => "4xx",
            Self::ServerError => "5xx",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum DecisionLabel {
    Permit,
    Deny,
    Review,
    Error,
}

impl From<DecisionKind> for DecisionLabel {
    fn from(value: DecisionKind) -> Self {
        match value {
            DecisionKind::Permit => Self::Permit,
            DecisionKind::Deny => Self::Deny,
            DecisionKind::Review => Self::Review,
            DecisionKind::Error => Self::Error,
        }
    }
}

impl DecisionLabel {
    fn as_str(self) -> &'static str {
        match self {
            Self::Permit => "PERMIT",
            Self::Deny => "DENY",
            Self::Review => "REVIEW",
            Self::Error => "ERROR",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum PolicyOutcomeLabel {
    Permit,
    Forbid,
    Error,
}

impl PolicyOutcomeLabel {
    fn as_str(self) -> &'static str {
        match self {
            Self::Permit => "PERMIT",
            Self::Forbid => "FORBID",
            Self::Error => "ERROR",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum RiskOutcomeLabel {
    Succeeded,
    Error,
    NotRun,
}

impl RiskOutcomeLabel {
    fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "SUCCEEDED",
            Self::Error => "ERROR",
            Self::NotRun => "NOT_RUN",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum SeverityLabel {
    Info,
    Medium,
    High,
    Critical,
}

impl SeverityLabel {
    fn as_str(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum IdempotencyOutcome {
    NewEvaluation,
    ExactRetry,
    Recovered,
    Conflict,
    InProgress,
}

impl IdempotencyOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::NewEvaluation => "NEW_EVALUATION",
            Self::ExactRetry => "EXACT_RETRY",
            Self::Recovered => "RECOVERED",
            Self::Conflict => "CONFLICT",
            Self::InProgress => "IN_PROGRESS",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum FreshnessLabel {
    NotProvided,
    NotYetValid,
    Fresh,
    Stale,
}

impl FreshnessLabel {
    fn as_str(self) -> &'static str {
        match self {
            Self::NotProvided => "NOT_PROVIDED",
            Self::NotYetValid => "NOT_YET_VALID",
            Self::Fresh => "FRESH",
            Self::Stale => "STALE",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum AuditOperation {
    AdmissionWrite,
    ContextWrite,
    DecisionWrite,
    PolicyWrite,
    ReadVerification,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum DependencyFailure {
    Database,
    ActivePolicy,
    HistorySnapshot,
    Audit,
    Lock,
}

impl DependencyFailure {
    fn as_str(self) -> &'static str {
        match self {
            Self::Database => "DATABASE",
            Self::ActivePolicy => "ACTIVE_POLICY",
            Self::HistorySnapshot => "HISTORY_SNAPSHOT",
            Self::Audit => "AUDIT",
            Self::Lock => "LOCK",
        }
    }
}

impl AuditOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::AdmissionWrite => "ADMISSION_WRITE",
            Self::ContextWrite => "CONTEXT_WRITE",
            Self::DecisionWrite => "DECISION_WRITE",
            Self::PolicyWrite => "POLICY_WRITE",
            Self::ReadVerification => "READ_VERIFICATION",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum RequestRejection {
    BodyTooLarge,
    HeadersTooLarge,
    RequestTimeout,
    EvaluationTimeout,
    SourceRateLimit,
    PrincipalRateLimit,
}

impl RequestRejection {
    fn as_str(self) -> &'static str {
        match self {
            Self::BodyTooLarge => "BODY_TOO_LARGE",
            Self::HeadersTooLarge => "HEADERS_TOO_LARGE",
            Self::RequestTimeout => "REQUEST_TIMEOUT",
            Self::EvaluationTimeout => "EVALUATION_TIMEOUT",
            Self::SourceRateLimit => "SOURCE_RATE_LIMIT",
            Self::PrincipalRateLimit => "PRINCIPAL_RATE_LIMIT",
        }
    }
}

impl GatewayTelemetry {
    pub(crate) fn request_dimensions(
        &self,
        request: &Request<axum::body::Body>,
    ) -> RequestDimensions {
        RequestDimensions {
            method: MethodLabel::from_method(request.method()),
            route: RouteLabel::from_request(request),
        }
    }

    pub(crate) fn record_request(
        &self,
        dimensions: RequestDimensions,
        status: StatusCode,
        duration: Duration,
    ) {
        let key = HttpKey {
            method: dimensions.method,
            route: dimensions.route,
            status: StatusClass::from_status(status),
        };
        let mut metrics = self.lock();
        let metric = metrics.http.entry(key).or_default();
        metric.count = metric.count.saturating_add(1);
        metric.duration.observe(duration);
    }

    pub(crate) fn record_decision(&self, kind: DecisionKind) {
        increment(&mut self.lock().decisions, kind.into(), 1);
    }

    pub(crate) fn record_policy(
        &self,
        outcome: PolicyOutcomeLabel,
        matched_policies: usize,
        duration: Duration,
    ) {
        let mut metrics = self.lock();
        metrics
            .policy_duration
            .entry(outcome)
            .or_default()
            .observe(duration);
        increment(
            &mut metrics.policy_matches,
            outcome,
            u64::try_from(matched_policies).unwrap_or(u64::MAX),
        );
    }

    pub(crate) fn record_risk(
        &self,
        outcome: RiskOutcomeLabel,
        duration: Duration,
        severities: impl IntoIterator<Item = SeverityLabel>,
    ) {
        let mut metrics = self.lock();
        metrics
            .risk_duration
            .entry(outcome)
            .or_default()
            .observe(duration);
        for severity in severities {
            increment(&mut metrics.risk_findings, severity, 1);
        }
    }

    pub(crate) fn record_idempotency(&self, outcome: IdempotencyOutcome) {
        increment(&mut self.lock().idempotency, outcome, 1);
    }

    pub(crate) fn record_freshness<'a>(
        &self,
        freshness: impl IntoIterator<Item = &'a EvidenceFreshness>,
    ) {
        let values: Vec<_> = freshness.into_iter().copied().collect();
        let mut metrics = self.lock();
        if values.is_empty() {
            increment(&mut metrics.freshness, FreshnessLabel::NotProvided, 1);
            return;
        }
        for value in values {
            let label = match value {
                EvidenceFreshness::NotYetValid => FreshnessLabel::NotYetValid,
                EvidenceFreshness::Fresh => FreshnessLabel::Fresh,
                EvidenceFreshness::Stale => FreshnessLabel::Stale,
            };
            increment(&mut metrics.freshness, label, 1);
        }
    }

    pub(crate) fn record_audit_failure(&self, operation: AuditOperation) {
        increment(&mut self.lock().audit_failures, operation, 1);
    }

    pub(crate) fn record_dependency_failure(&self, dependency: DependencyFailure) {
        increment(&mut self.lock().dependency_failures, dependency, 1);
    }

    pub(crate) fn record_request_rejection(&self, reason: RequestRejection) {
        increment(&mut self.lock().request_rejections, reason, 1);
    }

    pub(crate) fn render_prometheus(&self, replays: Option<DurableReplayCounts>) -> String {
        let metrics = self.lock();
        let mut output = String::with_capacity(16_384);
        output.push_str(
            "# HELP atf_gateway_http_requests_total Gateway HTTP responses by fixed route, method, and status class.\n\
             # TYPE atf_gateway_http_requests_total counter\n",
        );
        for (key, metric) in &metrics.http {
            let labels = http_labels(*key);
            writeln!(
                output,
                "atf_gateway_http_requests_total{{{labels}}} {}",
                metric.count
            )
            .expect("writing to String cannot fail");
        }
        output.push_str(
            "# HELP atf_gateway_http_request_duration_seconds Gateway HTTP response duration.\n\
             # TYPE atf_gateway_http_request_duration_seconds histogram\n",
        );
        for (key, metric) in &metrics.http {
            render_histogram(
                &mut output,
                "atf_gateway_http_request_duration_seconds",
                &http_labels(*key),
                &metric.duration,
            );
        }
        render_counter(
            &mut output,
            "atf_gateway_decisions_total",
            "Finalized Decisions by closed outcome.",
            "kind",
            metrics
                .decisions
                .iter()
                .map(|(label, value)| (label.as_str(), *value)),
        );
        render_histogram_map(
            &mut output,
            "atf_gateway_policy_evaluation_duration_seconds",
            "Policy evaluation duration by closed outcome.",
            "outcome",
            metrics
                .policy_duration
                .iter()
                .map(|(label, histogram)| (label.as_str(), histogram)),
        );
        render_counter(
            &mut output,
            "atf_gateway_policy_matches_total",
            "Matched Policy IDs counted without exposing Policy IDs.",
            "outcome",
            metrics
                .policy_matches
                .iter()
                .map(|(label, value)| (label.as_str(), *value)),
        );
        render_histogram_map(
            &mut output,
            "atf_gateway_risk_evaluation_duration_seconds",
            "Risk evaluation duration by closed outcome.",
            "outcome",
            metrics
                .risk_duration
                .iter()
                .map(|(label, histogram)| (label.as_str(), histogram)),
        );
        render_counter(
            &mut output,
            "atf_gateway_risk_findings_total",
            "Risk findings by closed severity; rule IDs are excluded.",
            "severity",
            metrics
                .risk_findings
                .iter()
                .map(|(label, value)| (label.as_str(), *value)),
        );
        render_counter(
            &mut output,
            "atf_gateway_idempotency_requests_total",
            "Idempotent admission outcomes.",
            "outcome",
            metrics
                .idempotency
                .iter()
                .map(|(label, value)| (label.as_str(), *value)),
        );
        output.push_str(
            "# HELP atf_gateway_replays_total Durable typed replay completion events by closed mode.\n\
             # TYPE atf_gateway_replays_total counter\n",
        );
        if let Some(replays) = replays {
            writeln!(
                output,
                "atf_gateway_replays_total{{mode=\"ORIGINAL\"}} {}",
                replays.original
            )
            .expect("writing to String cannot fail");
            writeln!(
                output,
                "atf_gateway_replays_total{{mode=\"COUNTERFACTUAL\"}} {}",
                replays.counterfactual
            )
            .expect("writing to String cannot fail");
        }
        output.push_str(
            "# HELP atf_gateway_replay_metrics_available Whether the durable replay aggregate was readable.\n\
             # TYPE atf_gateway_replay_metrics_available gauge\n",
        );
        writeln!(
            output,
            "atf_gateway_replay_metrics_available {}",
            u8::from(replays.is_some())
        )
        .expect("writing to String cannot fail");
        render_counter(
            &mut output,
            "atf_gateway_evidence_freshness_total",
            "Evidence freshness observations at evaluation time.",
            "state",
            metrics
                .freshness
                .iter()
                .map(|(label, value)| (label.as_str(), *value)),
        );
        render_counter(
            &mut output,
            "atf_gateway_audit_failures_total",
            "Audit append or verified-read failures by fixed operation.",
            "operation",
            metrics
                .audit_failures
                .iter()
                .map(|(label, value)| (label.as_str(), *value)),
        );
        render_counter(
            &mut output,
            "atf_gateway_dependency_failures_total",
            "Fail-closed serving dependency failures by closed dependency class.",
            "dependency",
            metrics
                .dependency_failures
                .iter()
                .map(|(label, value)| (label.as_str(), *value)),
        );
        render_counter(
            &mut output,
            "atf_gateway_request_rejections_total",
            "HTTP requests rejected by fixed operational safety boundary.",
            "reason",
            metrics
                .request_rejections
                .iter()
                .map(|(label, value)| (label.as_str(), *value)),
        );
        output
    }

    fn lock(&self) -> MutexGuard<'_, Metrics> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct RequestDimensions {
    method: MethodLabel,
    route: RouteLabel,
}

impl RequestDimensions {
    pub(crate) fn method(self) -> &'static str {
        self.method.as_str()
    }

    pub(crate) fn route(self) -> &'static str {
        self.route.as_str()
    }
}

fn increment<K: Ord>(metrics: &mut BTreeMap<K, u64>, key: K, amount: u64) {
    let value = metrics.entry(key).or_default();
    *value = value.saturating_add(amount);
}

fn http_labels(key: HttpKey) -> String {
    format!(
        "method=\"{}\",route=\"{}\",status_class=\"{}\"",
        key.method.as_str(),
        key.route.as_str(),
        key.status.as_str()
    )
}

fn render_counter<'a>(
    output: &mut String,
    name: &str,
    help: &str,
    label_name: &str,
    values: impl Iterator<Item = (&'a str, u64)>,
) {
    writeln!(output, "# HELP {name} {help}").expect("writing to String cannot fail");
    writeln!(output, "# TYPE {name} counter").expect("writing to String cannot fail");
    for (label, value) in values {
        writeln!(output, "{name}{{{label_name}=\"{label}\"}} {value}")
            .expect("writing to String cannot fail");
    }
}

fn render_histogram_map<'a>(
    output: &mut String,
    name: &str,
    help: &str,
    label_name: &str,
    values: impl Iterator<Item = (&'a str, &'a Histogram)>,
) {
    writeln!(output, "# HELP {name} {help}").expect("writing to String cannot fail");
    writeln!(output, "# TYPE {name} histogram").expect("writing to String cannot fail");
    for (label, histogram) in values {
        render_histogram(
            output,
            name,
            &format!("{label_name}=\"{label}\""),
            histogram,
        );
    }
}

fn render_histogram(output: &mut String, name: &str, labels: &str, histogram: &Histogram) {
    for ((upper_bound, count), label) in HISTOGRAM_BUCKETS_MICROS
        .iter()
        .zip(&histogram.buckets)
        .zip(HISTOGRAM_BUCKET_LABELS)
    {
        debug_assert_eq!(format_seconds(*upper_bound), label);
        writeln!(output, "{name}_bucket{{{labels},le=\"{label}\"}} {count}")
            .expect("writing to String cannot fail");
    }
    writeln!(
        output,
        "{name}_bucket{{{labels},le=\"+Inf\"}} {}",
        histogram.count
    )
    .expect("writing to String cannot fail");
    writeln!(
        output,
        "{name}_sum{{{labels}}} {}",
        format_seconds(histogram.sum_micros)
    )
    .expect("writing to String cannot fail");
    writeln!(output, "{name}_count{{{labels}}} {}", histogram.count)
        .expect("writing to String cannot fail");
}

fn format_seconds(micros: u64) -> String {
    let seconds = micros / 1_000_000;
    let fraction = micros % 1_000_000;
    if fraction == 0 {
        seconds.to_string()
    } else {
        format!("{seconds}.{fraction:06}")
            .trim_end_matches('0')
            .to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_format_is_exact_without_floating_point() {
        assert_eq!(format_seconds(0), "0");
        assert_eq!(format_seconds(1), "0.000001");
        assert_eq!(format_seconds(2_500), "0.0025");
        assert_eq!(format_seconds(1_250_000), "1.25");
    }
}
