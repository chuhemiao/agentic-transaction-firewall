#!/usr/bin/env python3
"""Validate and emit active, narrowly owned RustSec advisory exceptions."""

from __future__ import annotations

import datetime as dt
import re
import sys
import tomllib
from pathlib import Path


EXPECTED_TOP_LEVEL = {"schema_version", "exceptions"}
EXPECTED_EXCEPTION = {"id", "package", "version", "owner", "reason", "expires"}
ADVISORY_ID = re.compile(r"RUSTSEC-[0-9]{4}-[0-9]{4}")
OWNER = re.compile(r"@[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
PACKAGE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_-]*[A-Za-z0-9])?")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?")
MAX_LIFETIME = dt.timedelta(days=90)


def fail(message: str) -> None:
    print(f"invalid advisory exception policy: {message}", file=sys.stderr)
    raise SystemExit(1)


def parse_date(value: object, index: int) -> dt.date:
    if isinstance(value, dt.date):
        return value
    if isinstance(value, str):
        try:
            return dt.date.fromisoformat(value)
        except ValueError:
            pass
    fail(f"exceptions[{index}].expires must be an ISO-8601 date")


def main() -> None:
    if len(sys.argv) not in (2, 3):
        fail("usage: validate_advisory_exceptions.py <policy.toml> [cargo-tree.txt]")

    path = Path(sys.argv[1])
    try:
        policy = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(str(error))

    if set(policy) != EXPECTED_TOP_LEVEL:
        fail(f"top-level keys must be exactly {sorted(EXPECTED_TOP_LEVEL)}")
    if policy["schema_version"] != 1:
        fail("schema_version must be 1")
    exceptions = policy["exceptions"]
    if not isinstance(exceptions, list):
        fail("exceptions must be an array")

    today = dt.datetime.now(dt.timezone.utc).date()
    seen: set[str] = set()
    active: list[tuple[str, str, str]] = []
    for index, exception in enumerate(exceptions):
        if not isinstance(exception, dict) or set(exception) != EXPECTED_EXCEPTION:
            fail(
                f"exceptions[{index}] keys must be exactly "
                f"{sorted(EXPECTED_EXCEPTION)}"
            )

        advisory_id = exception["id"]
        package = exception["package"]
        version = exception["version"]
        owner = exception["owner"]
        reason = exception["reason"]
        if not isinstance(advisory_id, str) or ADVISORY_ID.fullmatch(advisory_id) is None:
            fail(f"exceptions[{index}].id must be one exact RUSTSEC advisory ID")
        if advisory_id in seen:
            fail(f"duplicate advisory exception {advisory_id}")
        if not isinstance(package, str) or PACKAGE.fullmatch(package) is None:
            fail(f"exceptions[{index}].package must be one exact package name")
        if not isinstance(version, str) or VERSION.fullmatch(version) is None:
            fail(f"exceptions[{index}].version must be one exact semantic version")
        if not isinstance(owner, str) or OWNER.fullmatch(owner) is None:
            fail(f"exceptions[{index}].owner must be one GitHub @owner")
        if not isinstance(reason, str) or len(reason.strip()) < 20:
            fail(f"exceptions[{index}].reason must state a specific reachability rationale")

        expires = parse_date(exception["expires"], index)
        if expires < today:
            fail(f"{advisory_id} expired on {expires.isoformat()}")
        if expires - today > MAX_LIFETIME:
            fail(f"{advisory_id} expiry exceeds the 90-day maximum")

        seen.add(advisory_id)
        active.append((advisory_id, package, version))

    if len(sys.argv) == 3:
        try:
            tree_lines = Path(sys.argv[2]).read_text(encoding="utf-8").splitlines()
            reachable = {
                (parts[0], parts[1].removeprefix("v"))
                for line in tree_lines
                if len(parts := line.split()) >= 2 and parts[1].startswith("v")
            }
        except OSError as error:
            fail(f"invalid cargo tree: {error}")

        for advisory_id, package_name, package_version in active:
            if (package_name, package_version) in reachable:
                fail(
                    f"{advisory_id} package {package_name}@{package_version} "
                    "is present in the all-feature/all-target Cargo tree"
                )

    print("\n".join(advisory_id for advisory_id, _, _ in active))


if __name__ == "__main__":
    main()
