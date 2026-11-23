#!/usr/bin/env python3
"""Build the approved IP Destination Policy v1 from IANA CSV snapshots."""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import sys
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT_ROOT = REPOSITORY_ROOT / "data" / "iana" / "ip-policy-v1"
DEFAULT_OUTPUT = (
    REPOSITORY_ROOT
    / "apps"
    / "api"
    / "src"
    / "threat_sentinel_api"
    / "data"
    / "ip_policy_v1.json"
)

SNAPSHOTS = {
    "ipv4_address_space": {
        "filename": "ipv4-address-space.csv",
        "count": 256,
        "sha256": "3cc77afcbc7a26c1716813a9b08c168e078f82ada22f3855d2466ba085b6d051",
        "headers": ["Prefix", "Designation", "Date", "WHOIS", "RDAP", "Status [1]", "Note"],
        "source_url": (
            "https://www.iana.org/assignments/ipv4-address-space/"
            "ipv4-address-space.csv"
        ),
        "iana_last_updated": "2025-10-10",
    },
    "ipv6_unicast_assignments": {
        "filename": "ipv6-unicast-address-assignments.csv",
        "count": 51,
        "sha256": "65d96c4fb7bfe5e314bb5832edb2f1957cfcfe764a7d983485a4e1704011ef18",
        "headers": ["Prefix", "Designation", "Date", "WHOIS", "RDAP", "Status", "Note"],
        "source_url": (
            "https://www.iana.org/assignments/ipv6-unicast-address-assignments/"
            "ipv6-unicast-address-assignments.csv"
        ),
        "iana_last_updated": "2025-10-10",
    },
    "ipv4_special_registry": {
        "filename": "iana-ipv4-special-registry-1.csv",
        "count": 25,
        "sha256": "cbc4b7653c8bc640ba1e8e5d4ebbf11e7c7a1d867e7f1593aad001d3f8632aac",
        "headers": [
            "Address Block",
            "Name",
            "RFC",
            "Allocation Date",
            "Termination Date",
            "Source",
            "Destination",
            "Forwardable",
            "Globally Reachable",
            "Reserved-by-Protocol",
        ],
        "source_url": (
            "https://www.iana.org/assignments/iana-ipv4-special-registry/"
            "iana-ipv4-special-registry-1.csv"
        ),
        "iana_last_updated": "2025-10-09",
    },
    "ipv6_special_registry": {
        "filename": "iana-ipv6-special-registry-1.csv",
        "count": 25,
        "sha256": "bf56772aef97fbf9b4a27c98b8511f2bb1ba96da4b9ccc12ab203a2496faba66",
        "headers": [
            "Address Block",
            "Name",
            "RFC",
            "Allocation Date",
            "Termination Date",
            "Source",
            "Destination",
            "Forwardable",
            "Globally Reachable",
            "Reserved-by-Protocol",
        ],
        "source_url": (
            "https://www.iana.org/assignments/iana-ipv6-special-registry/"
            "iana-ipv6-special-registry-1.csv"
        ),
        "iana_last_updated": "2025-10-09",
    },
}

EXPLICIT_IPV4: tuple[tuple[str, str], ...] = (
    ("192.88.99.0/24", "IPv4 deprecated 6to4 relay anycast"),
    ("168.63.129.16/32", "Azure platform address"),
)

EXPLICIT_IPV6: tuple[tuple[str, str], ...] = (
    ("::/96", "IPv4-compatible IPv6 address space"),
    ("2001::/32", "Teredo"),
    ("2002::/16", "6to4"),
    ("64:ff9b::/96", "IPv4-IPv6 NAT64 well-known prefix"),
    ("64:ff9b:1::/48", "IPv4-IPv6 NAT64 local-use prefix"),
)

EXPLICIT_IPV4_LIST = [prefix for prefix, _ in EXPLICIT_IPV4]
EXPLICIT_IPV6_LIST = [
    "::/96",
    "2002::/16",
    "2001::/32",
    "64:ff9b::/96",
    "64:ff9b:1::/48",
    "::ffff:0:0/96",
]


class SnapshotValidationError(RuntimeError):
    """Raised when an IANA snapshot fails strict validation."""


def validate_and_read(
    key: str,
) -> list[dict[str, str]]:
    spec = SNAPSHOTS[key]
    path = SNAPSHOT_ROOT / str(spec["filename"])
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    expected_digest = str(spec["sha256"])
    if digest != expected_digest:
        raise SnapshotValidationError(
            f"{path}: SHA-256 mismatch: expected {expected_digest}, got {digest}"
        )

    with path.open("r", encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames != spec["headers"]:
            raise SnapshotValidationError(
                f"{path}: CSV headers mismatch: expected {spec['headers']}, got {reader.fieldnames}"
            )
        rows = list(reader)

    expected_count = int(spec["count"])
    if len(rows) != expected_count:
        raise SnapshotValidationError(
            f"{path}: record count mismatch: expected {expected_count}, got {len(rows)}"
        )
    return rows


def strip_address_annotation(value: str) -> str:
    return value.strip().split(" ", 1)[0].split("[", 1)[0].strip()


def canonical_network(value: str) -> str:
    return str(ipaddress.ip_network(value, strict=True))


def split_address_blocks(value: str) -> list[str]:
    blocks: list[str] = []
    for item in value.split(","):
        item = strip_address_annotation(item)
        if not item:
            continue
        try:
            blocks.append(canonical_network(item))
        except ValueError as error:
            raise SnapshotValidationError(f"invalid address block {value!r}: {error}") from error
    return blocks


def clean_name(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    return value


def build_policy() -> dict[str, Any]:
    ipv4_rows = validate_and_read("ipv4_address_space")
    ipv6_rows = validate_and_read("ipv6_unicast_assignments")
    ipv4_special_rows = validate_and_read("ipv4_special_registry")
    ipv6_special_rows = validate_and_read("ipv6_special_registry")

    positive_ipv4: list[str] = []
    for row in ipv4_rows:
        status = row["Status [1]"]
        if status in {"ALLOCATED", "LEGACY"}:
            prefix = row["Prefix"].split("/", 1)[0].lstrip("0") or "0"
            first_octet = int(prefix)
            network = ipaddress.ip_network(f"{first_octet}.0.0.0/8", strict=True)
            positive_ipv4.append(str(network))

    positive_ipv4 = sorted(set(positive_ipv4), key=lambda value: ipaddress.ip_network(value))

    positive_ipv6: list[str] = []
    for row in ipv6_rows:
        if row["Status"] != "ALLOCATED":
            continue
        prefix = canonical_network(row["Prefix"])
        if prefix in {"2001::/23", "2002::/16"}:
            continue
        positive_ipv6.append(prefix)
    positive_ipv6 = sorted(
        set(positive_ipv6),
        key=lambda value: ipaddress.IPv6Network(value).network_address,
    )

    ipv4_deny: list[dict[str, str]] = []
    for row in ipv4_special_rows:
        name = clean_name(row["Name"])
        for prefix in split_address_blocks(row["Address Block"]):
            if prefix == "192.88.99.0/24":
                continue
            ipv4_deny.append({
                "prefix": prefix,
                "source": "ipv4_special_registry",
                "name": name,
            })
    if ipv4_deny[0]["prefix"] == "0.0.0.0/8" and ipv4_deny[1]["prefix"] == "0.0.0.0/32":
        ipv4_deny[0], ipv4_deny[1] = ipv4_deny[1], ipv4_deny[0]

    ipv4_deny.insert(
        next(
            index + 1
            for index, entry in enumerate(ipv4_deny)
            if entry["prefix"] == "127.0.0.0/8"
        ),
        {
            "prefix": "168.63.129.16/32",
            "source": "explicit_policy_v1",
            "name": "Azure platform address",
        },
    )
    ipv4_deny.insert(
        next(
            index + 1
            for index, entry in enumerate(ipv4_deny)
            if entry["prefix"] == "192.52.193.0/24"
        ),
        {
            "prefix": "192.88.99.0/24",
            "source": "explicit_policy_v1",
            "name": "IPv4 deprecated 6to4 relay anycast",
        },
    )

    ipv6_deny: list[dict[str, str]] = []
    ipv6_remaining: list[dict[str, str]] = []
    for row in ipv6_special_rows:
        name = clean_name(row["Name"])
        for prefix in split_address_blocks(row["Address Block"]):
            if prefix in {"64:ff9b::/96", "64:ff9b:1::/48", "2001::/32", "2002::/16"}:
                continue
            if prefix in {"::/128", "::1/128", "::ffff:0.0.0.0/96"}:
                continue
            ipv6_remaining.append({
                "prefix": prefix,
                "source": "ipv6_special_registry",
                "name": name,
            })
    ipv6_deny.extend([
        {"prefix": "::/128", "source": "ipv6_special_registry", "name": "Unspecified Address"},
        {
            "prefix": "::/96",
            "source": "explicit_policy_v1",
            "name": "IPv4-compatible IPv6 address space",
        },
        {"prefix": "::1/128", "source": "ipv6_special_registry", "name": "Loopback Address"},
        {
            "prefix": "::ffff:0.0.0.0/96",
            "source": "ipv6_special_registry",
            "name": "IPv4-mapped Address",
        },
        {
            "prefix": "64:ff9b::/96",
            "source": "explicit_policy_v1",
            "name": "IPv4-IPv6 NAT64 well-known prefix",
        },
        {
            "prefix": "64:ff9b:1::/48",
            "source": "explicit_policy_v1",
            "name": "IPv4-IPv6 NAT64 local-use prefix",
        },
    ])
    ipv6_deny.extend(ipv6_remaining)
    ipv6_deny.insert(
        next(index + 1 for index, entry in enumerate(ipv6_deny) if entry["prefix"] == "2001::/23"),
        {"prefix": "2001::/32", "source": "explicit_policy_v1", "name": "Teredo"},
    )
    ipv6_deny.insert(
        next(
            index + 1
            for index, entry in enumerate(ipv6_deny)
            if entry["prefix"] == "2001:db8::/32"
        ),
        {"prefix": "2002::/16", "source": "explicit_policy_v1", "name": "6to4"},
    )
    negative_deny = ipv4_deny + ipv6_deny

    provenance: dict[str, dict[str, Any]] = {}
    for key, spec in SNAPSHOTS.items():
        provenance[key] = {
            "source_url": str(spec["source_url"]),
            "retrieval_date": "2026-11-24",
            "iana_last_updated": str(spec["iana_last_updated"]),
            "sha256": str(spec["sha256"]),
            "parsed_record_count": int(spec["count"]),
            "snapshot_file": f"data/iana/ip-policy-v1/{spec['filename']}",
        }

    policy: dict[str, Any] = {
        "approved_at": "2026-11-24",
        "deny_precedence": "deny_overrides_allow",
        "explicit_exclusions": {
            "ipv4": EXPLICIT_IPV4_LIST,
            "ipv4_mapped_ipv6": "deny_all_addresses_in_::ffff:0:0/96",
            "ipv6": EXPLICIT_IPV6_LIST,
        },
        "negative_deny": negative_deny,
        "policy_id": "ip-destination-policy-v1",
        "policy_version": "1.0.0",
        "positive_allow": {
            "ipv4": positive_ipv4,
            "ipv6": positive_ipv6,
        },
        "provenance": provenance,
        "schema_version": 1,
    }
    canonical = json.dumps(
        policy,
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
    )
    policy["policy_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return policy


def render_policy(policy: dict[str, Any]) -> bytes:
    text = json.dumps(policy, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    return text.encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build IP Destination Policy v1 from validated IANA CSV snapshots."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="output policy JSON path",
    )
    args = parser.parse_args()

    try:
        policy = build_policy()
        output = args.output.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(render_policy(policy))
    except (OSError, SnapshotValidationError) as error:
        print(f"policy generation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
