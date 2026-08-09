#!/usr/bin/env python3
"""Validate and emit narrow, expiring Gitleaks fingerprints."""

from __future__ import annotations

import datetime as dt
import re
import sys
import tomllib
from pathlib import Path


EXPECTED_TOP_LEVEL = {"schema_version", "exceptions"}
EXPECTED_EXCEPTION = {"fingerprint", "owner", "reason", "expires"}
FINGERPRINT = re.compile(
    r"[0-9a-f]{40}:[^:\n]+:[A-Za-z0-9_-]+:[1-9][0-9]*"
)
OWNER = re.compile(r"@[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
MAX_LIFETIME = dt.timedelta(days=90)


def fail(message: str) -> None:
    print(f"invalid secret exception policy: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: validate_secret_exceptions.py <policy.toml>")
    try:
        policy = tomllib.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(str(error))

    if set(policy) != EXPECTED_TOP_LEVEL:
        fail(f"top-level keys must be exactly {sorted(EXPECTED_TOP_LEVEL)}")
    if policy["schema_version"] != 1 or not isinstance(policy["exceptions"], list):
        fail("schema_version must be 1 and exceptions must be an array")

    today = dt.datetime.now(dt.timezone.utc).date()
    seen: set[str] = set()
    active: list[str] = []
    for index, exception in enumerate(policy["exceptions"]):
        if not isinstance(exception, dict) or set(exception) != EXPECTED_EXCEPTION:
            fail(
                f"exceptions[{index}] keys must be exactly "
                f"{sorted(EXPECTED_EXCEPTION)}"
            )
        fingerprint = exception["fingerprint"]
        owner = exception["owner"]
        reason = exception["reason"]
        expires = exception["expires"]
        if not isinstance(fingerprint, str) or FINGERPRINT.fullmatch(fingerprint) is None:
            fail(f"exceptions[{index}].fingerprint must identify one committed finding")
        if fingerprint in seen:
            fail(f"duplicate fingerprint {fingerprint}")
        if not isinstance(owner, str) or OWNER.fullmatch(owner) is None:
            fail(f"exceptions[{index}].owner must be one GitHub @owner")
        if not isinstance(reason, str) or len(reason.strip()) < 20:
            fail(f"exceptions[{index}].reason must be specific")
        try:
            expiry = expires if isinstance(expires, dt.date) else dt.date.fromisoformat(expires)
        except (TypeError, ValueError):
            fail(f"exceptions[{index}].expires must be an ISO-8601 date")
        if expiry < today:
            fail(f"fingerprint {fingerprint} expired on {expiry.isoformat()}")
        if expiry - today > MAX_LIFETIME:
            fail(f"fingerprint {fingerprint} expiry exceeds the 90-day maximum")
        seen.add(fingerprint)
        active.append(fingerprint)

    print("\n".join(active))


if __name__ == "__main__":
    main()
