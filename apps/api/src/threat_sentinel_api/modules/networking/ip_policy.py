"""Versioned, local IP destination policy for IP address classification.

This module performs no DNS resolution or network I/O.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Final, Iterable


POLICY_PATH: Final = Path(__file__).resolve().parents[2] / "data" / "ip_policy_v1.json"
POLICY_VERSION: Final = "1.0.0"


class ClassificationDecision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class AddressPolicyError(ValueError):
    """Raised when the bundled policy cannot be loaded or validated."""


@dataclass(frozen=True, slots=True)
class AddressClassification:
    decision: ClassificationDecision
    reason: str
    canonical_address: str | None = None
    policy_version: str = POLICY_VERSION


@dataclass(frozen=True, slots=True)
class AddressSetClassification:
    decision: ClassificationDecision
    reason: str
    policy_version: str
    classifications: tuple[AddressClassification, ...]


@dataclass(frozen=True, slots=True)
class IPv4Policy:
    positive: tuple[ipaddress.IPv4Network, ...]
    deny: tuple[ipaddress.IPv4Network, ...]


@dataclass(frozen=True, slots=True)
class IPv6Policy:
    positive: tuple[ipaddress.IPv6Network, ...]
    deny: tuple[ipaddress.IPv6Network, ...]


@dataclass(frozen=True, slots=True)
class IPPolicy:
    policy_id: str
    policy_version: str
    positive_ipv4: tuple[ipaddress.IPv4Network, ...]
    negative_ipv4: tuple[ipaddress.IPv4Network, ...]
    positive_ipv6: tuple[ipaddress.IPv6Network, ...]
    negative_ipv6: tuple[ipaddress.IPv6Network, ...]


def _canonical_network(value: Any, version: int) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    if not isinstance(value, str) or not value or any(character.isspace() for character in value):
        raise AddressPolicyError("invalid_policy_network")
    try:
        network = ipaddress.ip_network(value, strict=True)
    except (TypeError, ValueError):
        raise AddressPolicyError("invalid_policy_network") from None
    if network.version != version:
        raise AddressPolicyError("invalid_policy_network")
    return network


def _validate_schema(policy: object) -> dict[str, Any]:
    if not isinstance(policy, dict):
        raise AddressPolicyError("invalid_policy_schema")
    required = {
        "policy_id",
        "policy_version",
        "approved_at",
        "schema_version",
        "provenance",
        "positive_allow",
        "negative_deny",
        "explicit_exclusions",
        "deny_precedence",
        "policy_sha256",
    }
    if set(policy) != required:
        raise AddressPolicyError("invalid_policy_schema")
    if policy["policy_id"] != "ip-destination-policy-v1":
        raise AddressPolicyError("invalid_policy_schema")
    if policy["policy_version"] != POLICY_VERSION:
        raise AddressPolicyError("invalid_policy_schema")
    if policy["schema_version"] != 1:
        raise AddressPolicyError("invalid_policy_schema")
    if policy["approved_at"] != "2026-11-24":
        raise AddressPolicyError("invalid_policy_schema")
    if policy["deny_precedence"] != "deny_overrides_allow":
        raise AddressPolicyError("invalid_policy_schema")
    if not isinstance(policy["policy_sha256"], str):
        raise AddressPolicyError("invalid_policy_schema")

    provenance = policy["provenance"]
    if not isinstance(provenance, dict) or len(provenance) != 4:
        raise AddressPolicyError("invalid_policy_schema")
    for source in provenance.values():
        if not isinstance(source, dict):
            raise AddressPolicyError("invalid_policy_schema")
        if set(source) != {
            "source_url",
            "retrieval_date",
            "iana_last_updated",
            "sha256",
            "parsed_record_count",
            "snapshot_file",
        }:
            raise AddressPolicyError("invalid_policy_schema")
        if source["retrieval_date"] != "2026-11-24":
            raise AddressPolicyError("invalid_policy_schema")
        if not isinstance(source["parsed_record_count"], int):
            raise AddressPolicyError("invalid_policy_schema")
        if not isinstance(source["sha256"], str) or len(source["sha256"]) != 64:
            raise AddressPolicyError("invalid_policy_schema")

    positive = policy["positive_allow"]
    negative = policy["negative_deny"]
    exclusions = policy["explicit_exclusions"]
    if not isinstance(positive, dict) or set(positive) != {"ipv4", "ipv6"}:
        raise AddressPolicyError("invalid_policy_schema")
    if not isinstance(negative, list):
        raise AddressPolicyError("invalid_policy_schema")
    if not isinstance(exclusions, dict):
        raise AddressPolicyError("invalid_policy_schema")
    return policy


def load_ip_policy(path: Path = POLICY_PATH) -> IPPolicy:
    """Load and validate only the bundled versioned policy data."""
    try:
        raw = path.read_text(encoding="utf-8")
        payload = _validate_schema(json.loads(raw))
    except (OSError, json.JSONDecodeError):
        raise AddressPolicyError("policy_load_failed") from None

    policy_without_checksum = dict(payload)
    checksum = policy_without_checksum.pop("policy_sha256")
    canonical = json.dumps(
        policy_without_checksum,
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
    )
    if hashlib.sha256(canonical.encode("utf-8")).hexdigest() != checksum:
        raise AddressPolicyError("policy_checksum_mismatch")

    positive = payload["positive_allow"]
    if not isinstance(positive["ipv4"], list) or not isinstance(positive["ipv6"], list):
        raise AddressPolicyError("invalid_policy_schema")

    positive_ipv4: list[ipaddress.IPv4Network] = []
    for value in positive["ipv4"]:
        network = _canonical_network(value, 4)
        assert isinstance(network, ipaddress.IPv4Network)
        positive_ipv4.append(network)

    positive_ipv6: list[ipaddress.IPv6Network] = []
    for value in positive["ipv6"]:
        network = _canonical_network(value, 6)
        assert isinstance(network, ipaddress.IPv6Network)
        positive_ipv6.append(network)

    negative_ipv4: list[ipaddress.IPv4Network] = []
    negative_ipv6: list[ipaddress.IPv6Network] = []
    seen_negative: set[str] = set()
    for entry in payload["negative_deny"]:
        if not isinstance(entry, dict) or set(entry) != {"prefix", "source", "name"}:
            raise AddressPolicyError("invalid_policy_schema")
        network = _canonical_network(entry["prefix"], 4 if ":" not in entry["prefix"] else 6)
        canonical = str(network)
        if canonical in seen_negative:
            raise AddressPolicyError("duplicate_policy_deny")
        seen_negative.add(canonical)
        if isinstance(network, ipaddress.IPv4Network):
            negative_ipv4.append(network)
        else:
            negative_ipv6.append(network)

    return IPPolicy(
        policy_id=payload["policy_id"],
        policy_version=payload["policy_version"],
        positive_ipv4=tuple(sorted(positive_ipv4, key=lambda network: network.network_address)),
        negative_ipv4=tuple(sorted(negative_ipv4, key=lambda network: network.network_address)),
        positive_ipv6=tuple(sorted(positive_ipv6, key=lambda network: network.network_address)),
        negative_ipv6=tuple(sorted(negative_ipv6, key=lambda network: network.network_address)),
    )


_POLICY: Final = load_ip_policy()


def _parse_strict_address(value: object) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if not isinstance(value, str):
        raise AddressPolicyError("invalid_address_type")
    if not value or any(character.isspace() for character in value):
        raise AddressPolicyError("malformed_address")
    if "/" in value or "%" in value or "[" in value or "]" in value:
        raise AddressPolicyError("unsupported_address_representation")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise AddressPolicyError("malformed_address") from None
    return address


def _in_network(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    networks: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> bool:
    return any(address in network for network in networks)


def classify_ip_address(value: object) -> AddressClassification:
    """Return an explicit allow or deny classification without network I/O."""
    try:
        address = _parse_strict_address(value)
    except AddressPolicyError as error:
        reason = str(error)
        return AddressClassification(
            decision=ClassificationDecision.DENY,
            reason=reason,
            canonical_address=None,
            policy_version=_POLICY.policy_version,
        )

    canonical = address.compressed
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return AddressClassification(
            ClassificationDecision.DENY,
            "ipv4_mapped_ipv6",
            canonical,
            _POLICY.policy_version,
        )

    if isinstance(address, ipaddress.IPv4Address):
        if _in_network(address, _POLICY.negative_ipv4):
            return AddressClassification(
                ClassificationDecision.DENY,
                "iana_ipv4_special_purpose_or_explicit_exclusion",
                canonical,
                _POLICY.policy_version,
            )
        if _in_network(address, _POLICY.positive_ipv4):
            return AddressClassification(
                ClassificationDecision.ALLOW,
                "ipv4_registry_positive_allow",
                canonical,
                _POLICY.policy_version,
            )
        return AddressClassification(
            ClassificationDecision.DENY,
            "outside_ipv4_positive_allow_boundary",
            canonical,
            _POLICY.policy_version,
        )

    if _in_network(address, _POLICY.negative_ipv6):
        return AddressClassification(
            ClassificationDecision.DENY,
            "iana_ipv6_special_purpose_or_explicit_exclusion",
            canonical,
            _POLICY.policy_version,
        )
    if _in_network(address, _POLICY.positive_ipv6):
        return AddressClassification(
            ClassificationDecision.ALLOW,
            "ipv6_rir_registry_positive_allow",
            canonical,
            _POLICY.policy_version,
        )
    return AddressClassification(
        ClassificationDecision.DENY,
        "outside_ipv6_positive_allow_boundary",
        canonical,
        _POLICY.policy_version,
    )


def evaluate_address_set(values: Iterable[object]) -> AddressSetClassification:
    """Reject the complete set if any address is denied or malformed."""
    try:
        items = tuple(values)
    except TypeError:
        return AddressSetClassification(
            ClassificationDecision.DENY,
            "invalid_address_set",
            _POLICY.policy_version,
            (),
        )
    if not items:
        return AddressSetClassification(
            ClassificationDecision.DENY,
            "empty_address_set",
            _POLICY.policy_version,
            (),
        )

    classifications = tuple(classify_ip_address(value) for value in items)
    denied = [item for item in classifications if item.decision is ClassificationDecision.DENY]
    if denied:
        return AddressSetClassification(
            ClassificationDecision.DENY,
            "address_set_contains_denied_address",
            _POLICY.policy_version,
            classifications,
        )
    return AddressSetClassification(
        ClassificationDecision.ALLOW,
        "all_addresses_allowed",
        _POLICY.policy_version,
        classifications,
    )
