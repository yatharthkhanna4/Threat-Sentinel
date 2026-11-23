from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta

import pytest

from threat_sentinel_api.modules.networking.types import (
    AddressFamily,
    AddressRecord,
    CanonicalAddress,
    CNAMELink,
    CNAMERecord,
    DNSResolutionError,
    FamilyResolution,
    FamilyResolutionStatus,
    MAX_CNAME_LINKS,
    MAX_DNS_TTL_SECONDS,
    MAX_TERMINAL_ADDRESSES,
    ResolutionStatus,
    ValidatedResolution,
)


def timestamp() -> datetime:
    return datetime(2026, 11, 24, tzinfo=UTC)


def valid_resolution(**overrides: object) -> ValidatedResolution:
    ipv4 = overrides.get("ipv4_addresses", ["8.8.8.8", "1.1.1.1"])
    ipv6 = overrides.get("ipv6_addresses", ["2001:4860:4860::8888"])
    cname_chain = overrides.get("cname_chain", [])
    terminal_owner = overrides.get("terminal_owner", "example.com")
    ipv4_status = "nodata" if not tuple(ipv4) else "addresses"
    ipv6_status = "nodata" if not tuple(ipv6) else "addresses"
    values: dict[str, object] = {
        "hostname": "Example.COM.",
        "ipv4_addresses": ipv4,
        "ipv6_addresses": ipv6,
        "cname_chain": cname_chain,
        "terminal_owner": terminal_owner,
        "resolved_at": timestamp(),
        "total_deadline": timestamp() + timedelta(seconds=10),
        "family_results": (
            FamilyResolution(
                AddressFamily.IPV4,
                terminal_owner,
                cname_chain,
                status=ipv4_status,
                addresses=() if ipv4_status == "nodata" else ipv4,
            ),
            FamilyResolution(
                AddressFamily.IPV6,
                terminal_owner,
                cname_chain,
                status=ipv6_status,
                addresses=() if ipv6_status == "nodata" else ipv6,
            ),
        ),
    }
    values.update(overrides)
    return ValidatedResolution(**values)


def test_valid_resolution_is_canonical_and_complete() -> None:
    resolution = valid_resolution()

    assert resolution.hostname == "example.com"
    assert resolution.terminal_owner == "example.com"
    assert resolution.status is ResolutionStatus.VALID
    assert resolution.policy_version == "1.0.0"
    assert resolution.ipv4_addresses == (
        CanonicalAddress("8.8.8.8"),
        CanonicalAddress("1.1.1.1"),
    )
    assert resolution.resolved_at.tzinfo is UTC
    assert resolution.total_deadline > resolution.resolved_at
    assert resolution.a_family.family is AddressFamily.IPV4
    assert resolution.aaaa_family.family is AddressFamily.IPV6


def test_valid_dual_family_nodata_resolution_is_representable() -> None:
    resolution = valid_resolution(
        ipv4_addresses=[],
        ipv6_addresses=["2001:4860:4866::8888"],
    )
    assert resolution.ipv4_addresses == ()
    assert len(resolution.ipv6_addresses) == 1


@pytest.mark.parametrize(
    "address",
    [
        "10.0.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "192.168.0.1",
        "2001:db8::1",
        "::ffff:8.8.8.8",
        "",
        "192.168.001.1",
        None,
    ],
)
def test_canonical_address_rejects_prohibited_malformed_and_typed_misvalues(
    address: object,
) -> None:
    with pytest.raises(DNSResolutionError):
        CanonicalAddress(address)


def test_mixed_answer_set_is_rejected_in_full_resolution() -> None:
    with pytest.raises(DNSResolutionError, match="prohibited_address"):
        valid_resolution(ipv4_addresses=["8.8.8.8", "10.0.0.1"])


def test_mixed_ipv4_ipv6_answer_set_is_rejected_by_family() -> None:
    with pytest.raises(DNSResolutionError, match="address_family_mismatch"):
        valid_resolution(ipv4_addresses=["2001:4860:4860::8888"])


def test_duplicate_addresses_are_rejected_after_canonicalization() -> None:
    with pytest.raises(DNSResolutionError, match="duplicate_address"):
        valid_resolution(ipv4_addresses=["8.8.8.8", "8.8.8.8"])


def test_duplicate_ipv6_addresses_are_rejected_after_canonicalization() -> None:
    with pytest.raises(DNSResolutionError, match="duplicate_address"):
        valid_resolution(
            ipv6_addresses=[
                "2001:4860:4860::8888",
                "2001:4860:4860:0:0:0:0:8888",
            ]
        )


def test_empty_resolution_is_rejected() -> None:
    with pytest.raises(DNSResolutionError, match="empty_address_set"):
        valid_resolution(ipv4_addresses=[], ipv6_addresses=[], terminal_owner="example.com")


def test_family_resolution_enforces_family_address_consistency() -> None:
    with pytest.raises(DNSResolutionError, match="address_family_mismatch"):
        FamilyResolution(
            AddressFamily.IPV4,
            "example.com",
            addresses=["2001:4860:4860::8888"],
        )


def test_family_nodata_cannot_contain_addresses() -> None:
    with pytest.raises(DNSResolutionError, match="nodata_with_addresses"):
        FamilyResolution(
            AddressFamily.IPV6,
            "example.com",
            status=FamilyResolutionStatus.NODATA,
            addresses=["2001:4860:4860::8888"],
        )


def test_valid_family_nodata_is_allowed() -> None:
    family = FamilyResolution(
        AddressFamily.IPV6,
        "example.com",
        status="nodata",
        addresses=[],
    )
    assert family.status is FamilyResolutionStatus.NODATA


def test_missing_a_family_outcome_is_rejected() -> None:
    aaaa = FamilyResolution(
        "ipv6",
        "example.com",
        addresses=["2001:4860:4860::8888"],
    )
    with pytest.raises(DNSResolutionError, match="missing_family_resolution"):
        ValidatedResolution(
            "example.com",
            ipv6_addresses=["2001:4860:4860::8888"],
            terminal_owner="example.com",
            resolved_at=timestamp(),
            total_deadline=timestamp(),
            family_results=(aaaa,),
        )


def test_missing_aaaa_family_outcome_is_rejected() -> None:
    a = FamilyResolution("ipv4", "example.com", addresses=["8.8.8.8"])
    with pytest.raises(DNSResolutionError, match="missing_family_resolution"):
        ValidatedResolution(
            "example.com",
            ipv4_addresses=["8.8.8.8"],
            terminal_owner="example.com",
            resolved_at=timestamp(),
            total_deadline=timestamp(),
            family_results=(a,),
        )


def test_duplicate_family_outcomes_are_rejected() -> None:
    a1 = FamilyResolution("ipv4", "example.com", addresses=["8.8.8.8"])
    a2 = FamilyResolution("ipv4", "example.com", addresses=["1.1.1.1"])
    aaaa = FamilyResolution(
        "ipv6",
        "example.com",
        status="nodata",
        addresses=[],
    )
    with pytest.raises(DNSResolutionError, match="duplicate_family_resolution"):
        ValidatedResolution(
            "example.com",
            ipv4_addresses=["8.8.8.8"],
            terminal_owner="example.com",
            resolved_at=timestamp(),
            total_deadline=timestamp(),
            family_results=(a1, a2, aaaa),
        )


def test_family_addresses_cannot_disagree_with_aggregate_addresses() -> None:
    a = FamilyResolution("ipv4", "example.com", addresses=["1.1.1.1"])
    aaaa = FamilyResolution(
        "ipv6",
        "example.com",
        status="nodata",
        addresses=[],
    )
    with pytest.raises(DNSResolutionError, match="family_address_mismatch"):
        ValidatedResolution(
            "example.com",
            ipv4_addresses=["8.8.8.8"],
            terminal_owner="example.com",
            resolved_at=timestamp(),
            total_deadline=timestamp(),
            family_results=(a, aaaa),
        )


def test_family_status_cannot_disagree_with_aggregate_addresses() -> None:
    a = FamilyResolution(
        "ipv4",
        "example.com",
        status="nodata",
        addresses=[],
    )
    aaaa = FamilyResolution(
        "ipv6",
        "example.com",
        status="nodata",
        addresses=[],
    )
    with pytest.raises(DNSResolutionError, match="family_status_mismatch"):
        ValidatedResolution(
            "example.com",
            ipv4_addresses=["8.8.8.8"],
            terminal_owner="example.com",
            resolved_at=timestamp(),
            total_deadline=timestamp(),
            family_results=(a, aaaa),
        )


def test_addresses_plus_aaaa_nodata_is_valid() -> None:
    resolution = valid_resolution(
        ipv4_addresses=["8.8.8.8"],
        ipv6_addresses=[],
    )
    assert resolution.a_family.status is FamilyResolutionStatus.ADDRESSES
    assert resolution.aaaa_family.status is FamilyResolutionStatus.NODATA


def test_a_nodata_plus_addresses_is_valid() -> None:
    resolution = valid_resolution(
        ipv4_addresses=[],
        ipv6_addresses=["2001:4860:4860::8888"],
    )
    assert resolution.a_family.status is FamilyResolutionStatus.NODATA
    assert resolution.aaaa_family.status is FamilyResolutionStatus.ADDRESSES


def test_cname_chain_is_owned_and_coherent() -> None:
    chain = (
        CNAMELink("example.com", "alias.example.net"),
        CNAMELink("alias.example.net", "target.example.net"),
    )
    resolution = valid_resolution(
        hostname="example.com",
        cname_chain=chain,
        terminal_owner="target.example.net",
    )
    assert resolution.cname_chain == chain


@pytest.mark.parametrize(
    ("chain", "error"),
    [
        (
            (
                CNAMELink("example.com", "a.example.net"),
                CNAMELink("b.example.net", "c.example.net"),
            ),
            "cname_chain_disjoint",
        ),
        (
            (
                CNAMELink("example.com", "a.example.net"),
                CNAMELink("a.example.net", "example.com"),
            ),
            "cname_cycle",
        ),
        (
            tuple(
                CNAMELink(
                    f"node-{index}.example",
                    f"node-{index + 1}.example",
                )
                for index in range(MAX_CNAME_LINKS + 1)
            ),
            "too_many_cname_links",
        ),
    ],
)
def test_invalid_cname_chains_are_rejected(chain: tuple[CNAMELink, ...], error: str) -> None:
    with pytest.raises(DNSResolutionError, match=error):
        valid_resolution(cname_chain=chain, terminal_owner=chain[-1].target)


def test_cname_owner_must_match_resolution_hostname() -> None:
    with pytest.raises(DNSResolutionError, match="cname_owner_mismatch"):
        valid_resolution(
            cname_chain=(CNAMELink("other.example", "target.example.net"),),
            terminal_owner="target.example.net",
        )


def test_cross_family_cname_mismatch_is_rejected() -> None:
    a = FamilyResolution(
        "ipv4",
        "target.example.net",
        (("example.com", "target.example.net"),),
        addresses=["8.8.8.8"],
    )
    b = FamilyResolution(
        "ipv6",
        "alias.example.net",
        (("example.com", "alias.example.net"),),
        addresses=["2001:4860:4860::8888"],
    )
    with pytest.raises(DNSResolutionError, match="cross_family_cname_mismatch"):
        ValidatedResolution(
            "example.com",
            ipv4_addresses=["8.8.8.8"],
            ipv6_addresses=["2001:4860:4860::8888"],
            cname_chain=(("example.com", "target.example.net"),),
            terminal_owner="target.example.net",
            resolved_at=timestamp(),
            total_deadline=timestamp(),
            family_results=(a, b),
        )


def test_cross_family_terminal_mismatch_is_rejected() -> None:
    a = FamilyResolution(
        "ipv4",
        "target-a.example.net",
        addresses=["8.8.8.8"],
    )
    b = FamilyResolution(
        "ipv6",
        "target-b.example.net",
        addresses=["2001:4860:4860::8888"],
    )
    with pytest.raises(DNSResolutionError, match="cross_family_terminal_mismatch"):
        ValidatedResolution(
            "example.com",
            ipv4_addresses=["8.8.8.8"],
            ipv6_addresses=["2001:4860:4860::8888"],
            cname_chain=(("example.com", "target-a.example.net"),),
            terminal_owner="target-a.example.net",
            resolved_at=timestamp(),
            total_deadline=timestamp(),
            family_results=(a, b),
        )


def test_incomplete_family_set_is_rejected() -> None:
    a = FamilyResolution("ipv4", "example.com", addresses=["8.8.8.8"])
    with pytest.raises(DNSResolutionError, match="missing_family_resolution"):
        ValidatedResolution(
            "example.com",
            ipv4_addresses=["8.8.8.8"],
            ipv6_addresses=["2001:4860:4860::8888"],
            terminal_owner="example.com",
            resolved_at=timestamp(),
            total_deadline=timestamp(),
            family_results=(a,),
        )


def test_total_address_limit_is_enforced_across_both_families() -> None:
    ipv4 = [f"8.8.{index // 256}.{index % 256}" for index in range(20)]
    ipv6 = [f"2001:4860:4860::{index:x}" for index in range(13)]
    with pytest.raises(DNSResolutionError, match="too_many_terminal_addresses"):
        valid_resolution(ipv4_addresses=ipv4, ipv6_addresses=ipv6)


def test_terminal_address_limit_is_enforced_per_answer_set() -> None:
    with pytest.raises(DNSResolutionError, match="too_many_terminal_addresses"):
        valid_resolution(
            ipv4_addresses=[
                f"8.8.{index // 256}.{index % 256}"
                for index in range(MAX_TERMINAL_ADDRESSES + 1)
            ]
        )


def test_ttl_boundaries_are_enforced() -> None:
    address = CanonicalAddress("8.8.8.8")
    assert AddressRecord(address, 0).ttl == 0
    assert AddressRecord(address, MAX_DNS_TTL_SECONDS).ttl == MAX_DNS_TTL_SECONDS
    with pytest.raises(DNSResolutionError, match="invalid_ttl"):
        AddressRecord(address, -1)
    with pytest.raises(DNSResolutionError, match="invalid_ttl"):
        AddressRecord(address, MAX_DNS_TTL_SECONDS + 1)


@pytest.mark.parametrize("ttl", [True, 1.0, "60", None])
def test_malformed_ttl_types_are_rejected(ttl: object) -> None:
    with pytest.raises(DNSResolutionError, match="invalid_ttl"):
        CNAMERecord("example.com", "target.example.net", ttl)


def test_resolution_rejects_naive_or_malformed_metadata() -> None:
    for resolved_at in (datetime(2026, 11, 24), "2026-11-24", None):
        with pytest.raises(DNSResolutionError):
            valid_resolution(resolved_at=resolved_at)


def test_resolution_rejects_deadline_before_resolution() -> None:
    with pytest.raises(DNSResolutionError, match="deadline_before_resolution"):
        valid_resolution(
            resolved_at=timestamp() + timedelta(seconds=11),
            total_deadline=timestamp() + timedelta(seconds=10),
        )


def test_resolution_rejects_malformed_hostname_and_policy_version() -> None:
    with pytest.raises(DNSResolutionError, match="invalid_hostname"):
        valid_resolution(hostname="localhost")
    with pytest.raises(DNSResolutionError, match="invalid_policy_version"):
        valid_resolution(policy_version="0.9")


def test_resolution_is_deeply_immutable() -> None:
    resolution = valid_resolution()
    ipv4 = resolution.ipv4_addresses

    with pytest.raises(FrozenInstanceError):
        resolution.status = ResolutionStatus.VALID
    with pytest.raises(AttributeError):
        resolution.cname_chain.append(CNAMELink("example.com", "target.example.net"))
    with pytest.raises(FrozenInstanceError):
        ipv4[0].address = "1.1.1.1"
