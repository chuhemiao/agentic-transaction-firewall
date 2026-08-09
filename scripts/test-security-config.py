#!/usr/bin/env python3
"""Verify that DS-038 security gates are wired into pull-request CI."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
DEPENDABOT = ROOT / ".github" / "dependabot.yml"


def require(condition: bool, message: str) -> None:
    if not condition:
        print(f"security configuration error: {message}", file=sys.stderr)
        raise SystemExit(1)


workflow = WORKFLOW.read_text(encoding="utf-8")

require(re.search(r"^\s*pull_request:\s*$", workflow, re.MULTILINE) is not None,
        "CI must run on every pull request")

action_refs = re.findall(r"^\s*-\s+uses:\s+([^\s#]+)", workflow, re.MULTILINE)
require(action_refs, "CI must declare at least one GitHub Action")
unpinned = [ref for ref in action_refs if re.fullmatch(r"[^@]+@[0-9a-f]{40}", ref) is None]
require(not unpinned, f"Actions must use immutable 40-character commits: {unpinned}")
service_images = re.findall(r"^\s+image:\s+([^\s#]+)", workflow, re.MULTILINE)
require(all(re.fullmatch(r"[^@]+@sha256:[0-9a-f]{64}", image) for image in service_images),
        "CI service images must use immutable sha256 manifests")

require("./scripts/test-security.sh" in workflow,
        "dependency and secret gate is not invoked by CI")
require("./scripts/test-rust-sast.sh" in workflow,
        "Rust SAST gate is not invoked by CI")

require(DEPENDABOT.is_file(), "missing .github/dependabot.yml")
dependabot = DEPENDABOT.read_text(encoding="utf-8")
require('package-ecosystem: "cargo"' in dependabot,
        "Dependabot must monitor Cargo dependencies")
require(dependabot.count('package-ecosystem: "cargo"') == 2 and
        'directory: "/fuzz"' in dependabot,
        "Dependabot must monitor both root and fuzz Cargo workspaces")
require('package-ecosystem: "github-actions"' in dependabot,
        "Dependabot must monitor GitHub Actions")

deny_policy = tomllib.loads((ROOT / "deny.toml").read_text(encoding="utf-8"))
deny_ignores = set(deny_policy["advisories"]["ignore"])
require(not deny_ignores,
        "cargo-deny graph advisory ignores must stay empty")

exception_policy = tomllib.loads(
    (ROOT / "security" / "advisory-exceptions.toml").read_text(encoding="utf-8")
)
locked_packages: set[tuple[str, str]] = set()
for lockfile in (ROOT / "Cargo.lock", ROOT / "fuzz" / "Cargo.lock"):
    lock = tomllib.loads(lockfile.read_text(encoding="utf-8"))
    locked_packages.update((package["name"], package["version"])
                           for package in lock["package"])
for exception in exception_policy["exceptions"]:
    require((exception["package"], exception["version"]) in locked_packages,
            f"stale advisory exception package: {exception['package']}@{exception['version']}")

print("DS-038 CI security configuration is pinned and wired")
