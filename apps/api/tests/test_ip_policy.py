import csv
import hashlib
import ipaddress
import json
import subprocess
import sys
from pathlib import Path

import pytest

from threat_sentinel_api.modules.networking.ip_policy import (
    AddressPolicyError,
    ClassificationDecision,
    classify_ip_address,
    evaluate_address_set,
    load_ip_policy,
)


API_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = API_ROOT.parents[1]
POLICY_PATH = API_ROOT / "src" / "threat_sentinel_api" / "data" / "ip_policy_v1.json"
REGISTRY_ROOT = REPOSITORY_ROOT / "data" / "iana" / "ip-policy-v1"


@pytest.fixture(scope="module")
def policy_data() -> dict[str, object]:
    return json.loads(POLICY_PATH.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    ("address", "reason"),
    [
        ("8.8.8.8", "ipv4_registry_positive_allow"),
        ("1.1.1.1", "ipv4_registry_positive_allow"),
        ("17.0.0.1", "ipv4_registry_positive_allow"),
        ("45.9.0.1", "ipv4_registry_positive_allow"),
    ],
)
def test_representative_allocated_ipv4_addresses_are_allowed(
    address: str,
    reason: str,
) -> None:
    result = classify_ip_address(address)
    assert result.decision is ClassificationDecision.ALLOW
    assert result.reason == reason


@pytest.mark.parametrize("address", ["11.0.0.1", "128.0.0.1"])
def test_legacy_ipv4_addresses_are_allowed(address: str) -> None:
    assert classify_ip_address(address).decision is ClassificationDecision.ALLOW


@pytest.mark.parametrize("address", ["0.0.0.1", "127.0.0.1", "240.0.0.1", "255.255.255.255"])
def test_reserved_ipv4_addresses_are_denied(address: str) -> None:
    result = classify_ip_address(address)
    assert result.decision is ClassificationDecision.DENY
    assert "special_purpose" in result.reason or "positive_allow_boundary" in result.reason


@pytest.mark.parametrize(
    ("address", "reason"),
    [
        ("2001:4860:4860::8888", "ipv6_rir_registry_positive_allow"),
        ("2606:4700:4700::1111", "ipv6_rir_registry_positive_allow"),
        ("2400:cb00::1", "ipv6_rir_registry_positive_allow"),
        ("2a00:1450:4001::1", "ipv6_rir_registry_positive_allow"),
        ("2800:3f0:4001::1", "ipv6_rir_registry_positive_allow"),
        ("2c00:1::1", "ipv6_rir_registry_positive_allow"),
    ],
)
def test_rir_allocated_ipv6_addresses_are_allowed(address: str, reason: str) -> None:
    result = classify_ip_address(address)
    assert result.decision is ClassificationDecision.ALLOW
    assert result.reason == reason


@pytest.mark.parametrize(
    "address",
    [
        "2001::1",
        "2001:db8::1",
        "2001:1::1",
        "2001:20::1",
        "2d00::1",
        "3fff::1",
        "4000::1",
        "ffff::1",
    ],
)
def test_non_rir_reserved_or_unlisted_ipv6_addresses_are_denied(address: str) -> None:
    assert classify_ip_address(address).decision is ClassificationDecision.DENY


@pytest.mark.parametrize(
    "address",
    [
        "10.0.0.1",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "172.16.0.1",
        "192.0.2.1",
        "192.168.0.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "192.88.99.1",
        "168.63.129.16",
    ],
)
def test_special_private_and_explicit_ipv4_exclusions_are_denied(address: str) -> None:
    assert classify_ip_address(address).decision is ClassificationDecision.DENY


@pytest.mark.parametrize(
    "address",
    [
        "::",
        "::1",
        "::ffff:8.8.8.8",
        "64:ff9b::808:808",
        "64:ff9b:1::1",
        "::1",
        "::2",
        "2002:0808:0808::1",
        "2001::1",
        "2001:0:4136:e378:8000:63bf:3fff:fdd2",
        "fc00::1",
        "fd00:ec2::254",
        "fe80::1",
        "ff00::1",
        "2001:db8::1",
        "2001:2::1",
        "3fff::1",
    ],
)
def test_special_transition_translation_and_metadata_ipv6_addresses_are_denied(
    address: str,
) -> None:
    assert classify_ip_address(address).decision is ClassificationDecision.DENY


def test_every_special_registry_prefix_is_denied(policy_data: dict[str, object]) -> None:
    entries = policy_data["negative_deny"]
    assert isinstance(entries, list)
    special_entries = [
        entry
        for entry in entries
        if entry["source"] in {"ipv4_special_registry", "ipv6_special_registry"}
    ]
    assert special_entries
    for entry in special_entries:
        network = ipaddress.ip_network(entry["prefix"], strict=True)
        representative = network.network_address
        if representative.compressed == "::ffff:0:0":
            representative = ipaddress.ip_address("::ffff:8.8.8.8")
        result = classify_ip_address(representative.compressed)
        assert result.decision is ClassificationDecision.DENY, entry


@pytest.mark.parametrize(
    "address",
    [
        "192.0.0.8",
        "192.0.0.9",
        "192.0.0.10",
        "192.0.0.170",
        "192.0.0.171",
    ],
)
def test_overlapping_parent_child_special_prefixes_are_denied(address: str) -> None:
    assert classify_ip_address(address).decision is ClassificationDecision.DENY


def test_mixed_address_set_is_denied_if_one_address_is_prohibited() -> None:
    result = evaluate_address_set(["8.8.8.8", "2001:4860:4860::8888", "169.254.169.254"])
    assert result.decision is ClassificationDecision.DENY
    assert result.reason == "address_set_contains_denied_address"
    assert len(result.classifications) == 3
    assert result.classifications[2].reason.startswith("iana_ipv4_special")


def test_mixed_set_of_allowed_addresses_is_allowed() -> None:
    result = evaluate_address_set(["8.8.8.8", "2001:4860:4860::8888"])
    assert result.decision is ClassificationDecision.ALLOW
    assert result.reason == "all_addresses_allowed"


@pytest.mark.parametrize(
    "value",
    [
        "",
        " ",
        "192.168.001.1",
        "127.1",
        "2130706433",
        "0x7f000001",
        "2001:db8::gg",
        "2001:db8::1/128",
        "[2001:4860:4860::8888]",
        "fe80::1%eth0",
        None,
        123,
    ],
)
def test_malformed_or_unsupported_addresses_are_denied(value: object) -> None:
    result = classify_ip_address(value)
    assert result.decision is ClassificationDecision.DENY
    assert result.canonical_address is None


def test_empty_and_invalid_address_sets_are_denied() -> None:
    assert evaluate_address_set([]).decision is ClassificationDecision.DENY
    assert evaluate_address_set(None).decision is ClassificationDecision.DENY  # type: ignore[arg-type]


def test_policy_snapshot_checksum_and_schema_are_valid(
    policy_data: dict[str, object],
) -> None:
    policy = dict(policy_data)
    checksum = policy.pop("policy_sha256")
    canonical = json.dumps(policy, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    assert isinstance(checksum, str)
    assert hashlib.sha256(canonical.encode("utf-8")).hexdigest() == checksum
    assert policy["policy_version"] == "1.0.0"
    assert policy["schema_version"] == 1
    assert policy["deny_precedence"] == "deny_overrides_allow"
    assert len(policy["provenance"]) == 4


@pytest.mark.parametrize(
    ("filename", "expected_count", "sha256"),
    [
        (
            "ipv4-address-space.csv",
            256,
            "3cc77afcbc7a26c1716813a9b08c168e078f82ada22f3855d2466ba085b6d051",
        ),
        (
            "ipv6-unicast-address-assignments.csv",
            51,
            "65d96c4fb7bfe5e314bb5832edb2f1957cfcfe764a7d983485a4e1704011ef18",
        ),
        (
            "iana-ipv4-special-registry-1.csv",
            25,
            "cbc4b7653c8bc640ba1e8e5d4ebbf11e7c7a1d867e7f1593aad001d3f8632aac",
        ),
        (
            "iana-ipv6-special-registry-1.csv",
            25,
            "bf56772aef97fbf9b4a27c98b8511f2bb1ba96da4b9ccc12ab203a2496faba66",
        ),
    ],
)
def test_authoritative_registry_snapshot_checksum_and_record_count(
    filename: str,
    expected_count: int,
    sha256: str,
) -> None:
    path = REGISTRY_ROOT / filename
    assert hashlib.sha256(path.read_bytes()).hexdigest() == sha256
    with path.open(newline="", encoding="utf-8-sig") as source:
        assert sum(1 for _ in csv.DictReader(source)) == expected_count


def test_local_policy_loader_rejects_missing_or_bad_payload(tmp_path: Path) -> None:
    bad = tmp_path / "bad-policy.json"
    bad.write_text("{}", encoding="utf-8")
    with pytest.raises(AddressPolicyError):
        load_ip_policy(bad)


def test_ip_policy_generator_is_reproducible(tmp_path: Path) -> None:
    generated = tmp_path / "ip_policy_v1.json"
    generator = REPOSITORY_ROOT / "scripts" / "build_ip_policy.py"
    subprocess.run(
        [sys.executable, str(generator), "--output", str(generated)],
        check=True,
        cwd=REPOSITORY_ROOT,
    )
    assert generated.read_bytes() == POLICY_PATH.read_bytes()
