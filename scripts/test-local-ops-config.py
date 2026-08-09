#!/usr/bin/env python3
"""Fail closed when the DS-040 supported-local operations contract drifts."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def require(condition: bool, message: str) -> None:
    if not condition:
        print(f"local operations configuration error: {message}", file=sys.stderr)
        raise SystemExit(1)


required_files = [
    "deploy/docker/compose.yml",
    "deploy/docker/gateway.Dockerfile",
    "deploy/docker/edge.Dockerfile",
    "deploy/docker/Caddyfile",
    "deploy/docker/idp/.well-known/openid-configuration",
    "deploy/docker/idp/jwks.json",
    "deploy/docker/local/edge.sh",
    "deploy/docker/local/bootstrap.sh",
    "deploy/docker/local/init-operations.sh",
    "deploy/docker/local/run-e2e.sh",
    "deploy/docker/local/backup-restore.sh",
    "deploy/docker/local/policy-rollback.sh",
    "deploy/docker/local/run-load.sh",
    "cli/atf-cli/src/bin/atf-shadow-load.rs",
    "docs/quickstart.md",
    "conformance/load/README.md",
]
for relative in required_files:
    require((ROOT / relative).is_file(), f"missing {relative}")

compose = (ROOT / "deploy/docker/compose.yml").read_text(encoding="utf-8")
require(re.search(r"^name:\s+atf-local$", compose, re.MULTILINE) is not None,
        "Compose project name must be atf-local")
for service in ("postgres", "edge", "metrics-init", "migrate", "bootstrap", "gateway", "ops"):
    require(re.search(rf"^  {service}:\s*$", compose, re.MULTILINE) is not None,
            f"missing {service} service")

immutable_images = re.findall(r"^\s+image:\s+([^\s#]+)", compose, re.MULTILINE)
require(immutable_images, "Compose must declare immutable external images")
for image in immutable_images:
    if (image.startswith("atf-local:") or image.startswith("${ATF_LOCAL_IMAGE")
            or image.startswith("${ATF_LOCAL_EDGE_IMAGE")):
        continue
    require(re.fullmatch(r"[^@]+@sha256:[0-9a-f]{64}", image) is not None,
            f"external image is not digest pinned: {image}")

require("127.0.0.1:${ATF_LOCAL_HTTPS_PORT:-8443}:8443" in compose,
        "business TLS edge must bind a loopback host port")
require("127.0.0.1:${ATF_LOCAL_METRICS_HTTPS_PORT:-9443}:9443" in compose,
        "operations TLS edge must bind a distinct loopback host port")
services_text = compose.split("\nservices:\n", 1)[1].split("\nvolumes:\n", 1)[0]


def service_block(name: str) -> str:
    start = re.search(rf"^  {re.escape(name)}:\s*$", services_text, re.MULTILINE)
    require(start is not None, f"missing {name} service")
    next_service = re.search(r"^  [A-Za-z0-9_-]+:\s*$", services_text[start.end():],
                             re.MULTILINE)
    end = start.end() + next_service.start() if next_service else len(services_text)
    return services_text[start.end():end]


for private_service in ("postgres", "gateway"):
    require(re.search(r"^    ports:\s*$", service_block(private_service), re.MULTILINE) is None,
            f"{private_service} must not publish a direct host port")
require("ATF_TLS_TERMINATED_BY_TRUSTED_PROXY: \"true\"" in compose,
        "Gateway must know the private edge terminated TLS")
require("ATF_METRICS_SOCKET_PATH: /run/atf/metrics.sock" in service_block("gateway"),
        "Gateway must bind the exact protected Metrics socket")
require("metrics-socket:/run/atf" in service_block("gateway") and
        "metrics-socket:/run/atf" in service_block("edge"),
        "only Gateway and edge must share the Metrics socket boundary")
require("metrics-trust:/metrics-trust:ro" in service_block("edge"),
        "edge must receive the Metrics client trust pool read-only")
require("metrics-authority:/metrics-authority" in service_block("metrics-init"),
        "one-shot Metrics initializer must own the client CA authority volume")
for service in ("edge", "gateway", "ops"):
    require("metrics-authority" not in service_block(service),
            f"{service} must never receive the Metrics client CA private authority")
for service in ("edge", "gateway"):
    require("metrics-client" not in service_block(service),
            f"{service} must never receive the Metrics reader private key")
require("metrics-client:/metrics-client:ro" in service_block("ops"),
        "operations tool must receive the generated Metrics credential read-only")
require("internal: true" in compose, "backend network must be internal")
require("service_completed_successfully" in compose,
        "Gateway must wait for migration/bootstrap completion")
require("no-new-privileges:true" in compose,
        "containers must opt out of privilege escalation")
require("atf-data:" in compose and "caddy-data:" in compose,
        "durable database and local CA state must use named volumes")
require("local-ca:/local-ca:ro" in compose,
        "Gateway and operations must receive only the public CA certificate")
for volume in ("metrics-authority", "metrics-client", "metrics-invalid",
               "metrics-socket", "metrics-trust"):
    require(f"  {volume}:" in compose, f"missing named {volume} volume")

dockerfile = (ROOT / "deploy/docker/gateway.Dockerfile").read_text(encoding="utf-8")
from_refs = re.findall(r"^FROM\s+([^\s]+)", dockerfile, re.MULTILINE)
require(len(from_refs) == 2, "Gateway image must have builder and runtime stages")
require(all(re.fullmatch(r"[^@]+@sha256:[0-9a-f]{64}", ref) for ref in from_refs),
        f"Dockerfile bases must be digest pinned: {from_refs}")
for binary in ("atf-gateway", "atf-store-migrate", "atf", "atf-shadow-load"):
    require(binary in dockerfile, f"runtime image does not include {binary}")
require("USER postgres" in dockerfile, "runtime must use a non-root user")
require("chown postgres:2000 /run/atf" in dockerfile and "chmod 02710 /run/atf" in dockerfile,
        "runtime image must pre-provision a non-replaceable shared socket directory")

edge_dockerfile = (ROOT / "deploy/docker/edge.Dockerfile").read_text(encoding="utf-8")
edge_from_refs = re.findall(r"^FROM\s+([^\s]+)", edge_dockerfile, re.MULTILINE)
require(len(edge_from_refs) == 1, "Edge image must have exactly one base")
require(re.fullmatch(r"[^@]+@sha256:[0-9a-f]{64}", edge_from_refs[0]) is not None,
        f"Edge Dockerfile base must be digest pinned: {edge_from_refs}")
require("setcap -r /usr/bin/caddy" in edge_dockerfile,
        "Edge image must remove the unnecessary privileged-port capability")
require("ENTRYPOINT [\"/usr/local/bin/atf-local-edge\"]" in edge_dockerfile,
        "Edge image must export its public root certificate")

caddy = (ROOT / "deploy/docker/Caddyfile").read_text(encoding="utf-8")
require("tls internal" in caddy, "local ingress and issuer must use generated TLS")
require("reverse_proxy gateway:8080" in caddy,
        "edge must be the only path to Gateway")
for boundary in ("https://localhost:9443", "mode require_and_verify",
                 "trust_pool file /metrics-trust/client-ca.crt",
                 "unix//run/atf/metrics.sock", "X-ATF-Operations-Verified MTLS_V1",
                 "{http.request.tls.client.public_key_sha256}"):
    require(boundary in caddy, f"Caddy Metrics boundary omits {boundary}")
require("handle /metrics" in caddy and "respond 404" in caddy,
        "business edge must terminate /metrics without proxying it")
business_site = caddy.split("https://localhost:9443", 1)[0]
for assertion_header in ("X-ATF-Operations-Verified",
                         "X-ATF-Operations-Public-Key"):
    require(f"header_up -{assertion_header}" in business_site,
            f"business edge must strip caller-supplied {assertion_header}")

pki_init = (ROOT / "deploy/docker/local/init-operations.sh").read_text(encoding="utf-8")
for control in ("ED25519", "extendedKeyUsage=", "clientAuth", "serverAuth",
                "ATF_ROTATE_METRICS_PKI", "approved-public-key-sha256",
                "-not_before", "-not_after", "umask 077"):
    require(control in pki_init, f"Metrics PKI lifecycle omits {control}")
require("BEGIN PRIVATE KEY" not in pki_init,
        "Metrics PKI source must not contain committed private-key material")

load_source = (ROOT / "cli/atf-cli/src/bin/atf-shadow-load.rs").read_text(
    encoding="utf-8"
)
for evidence in ("p95_milliseconds", "throughput_per_second", "decision_hash"):
    require(evidence in load_source, f"load report omits {evidence}")
require("f64" not in load_source and "f32" not in load_source,
        "load evidence must not add floating point to ATF Rust code")
for metrics_client in ("Command::Metrics", "Identity::from_pem", "MAX_METRICS_BYTES",
                       "replay_metrics_available"):
    require(metrics_client in load_source,
            f"bounded authenticated Metrics client omits {metrics_client}")

e2e = (ROOT / "deploy/docker/local/run-e2e.sh").read_text(encoding="utf-8")
for proof in ("restart", "replay original", "matched: true", "readyz",
              "wrong-client", "wrong-eku", "unapproved", "expired", "future",
              "replay_metrics_available=0", "ATF_ROTATE_METRICS_PKI"):
    require(proof in e2e, f"E2E does not prove {proof}")

restore = (ROOT / "deploy/docker/local/backup-restore.sh").read_text(encoding="utf-8")
for proof in ("pg_dump", "pg_restore", "audit_chain_heads", "replay original"):
    require(proof in restore, f"restore drill does not prove {proof}")

print("DS-040 authenticated Metrics configuration is closed and reproducible")
