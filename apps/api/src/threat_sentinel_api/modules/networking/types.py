"""Immutable address and resolution types for Phase 3B.4."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
import ipaddress
from typing import Iterable, NoReturn

from threat_sentinel_api.modules.targets.hostname import (
    CanonicalHostname,
    canonicalize_hostname,
)

from .ip_policy import (
    ClassificationDecision,
    POLICY_VERSION,
    classify_ip_address,
)


MAX_CNAME_LINKS = 8
MAX_TERMINAL_ADDRESSES = 32
MAX_DNS_TTL_SECONDS = 2**32 - 1


class DNSResolutionError(ValueError):
    """Stable error raised for invalid immutable resolution values."""


class AddressFamily(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    A = "ipv4"
    AAAA = "ipv6"


class ResolutionStatus(StrEnum):
    VALID = "valid"
    SUCCESS = "valid"


class FamilyResolutionStatus(StrEnum):
    ADDRESSES = "addresses"
    NODATA = "nodata"


def _reject(code: str) -> NoReturn:
    raise DNSResolutionError(code)


def _canonical_hostname(value: object) -> CanonicalHostname:
    if not isinstance(value, (str, CanonicalHostname)):
        _reject("invalid_hostname")
    try:
        return canonicalize_hostname(value)
    except (TypeError, ValueError):
        _reject("invalid_hostname")


@dataclass(frozen=True, slots=True)
class CanonicalAddress:
    address: str
    family: AddressFamily

    def __init__(self, value: object) -> None:
        if not isinstance(value, str):
            _reject("invalid_address_type")
        classification = classify_ip_address(value)
        if classification.decision is ClassificationDecision.DENY:
            _reject("prohibited_address")
        if classification.canonical_address is None:
            _reject("malformed_address")

        canonical_address = classification.canonical_address
        if canonical_address is None:
            _reject("malformed_address")
        parsed = ipaddress.ip_address(canonical_address)
        family = AddressFamily.IPV4 if parsed.version == 4 else AddressFamily.IPV6
        object.__setattr__(self, "address", parsed.compressed)
        object.__setattr__(self, "family", family)

    @property
    def canonical_address(self) -> str:
        return self.address


@dataclass(frozen=True, slots=True)
class AddressRecord:
    address: CanonicalAddress
    ttl: int

    def __init__(self, address: object, ttl: object) -> None:
        if not isinstance(ttl, int) or isinstance(ttl, bool):
            _reject("invalid_ttl")
        if ttl < 0 or ttl > MAX_DNS_TTL_SECONDS:
            _reject("invalid_ttl")
        canonical = address if isinstance(address, CanonicalAddress) else CanonicalAddress(address)
        object.__setattr__(self, "address", canonical)
        object.__setattr__(self, "ttl", ttl)


@dataclass(frozen=True, slots=True)
class CNAMELink:
    owner: CanonicalHostname
    target: CanonicalHostname

    def __init__(self, owner: object, target: object) -> None:
        canonical_owner = _canonical_hostname(owner)
        canonical_target = _canonical_hostname(target)
        object.__setattr__(self, "owner", canonical_owner)
        object.__setattr__(self, "target", canonical_target)


CNAMEHop = CNAMELink


@dataclass(frozen=True, slots=True)
class CNAMERecord:
    owner: CanonicalHostname
    target: CanonicalHostname
    ttl: int

    def __init__(self, owner: object, target: object, ttl: object) -> None:
        if not isinstance(ttl, int) or isinstance(ttl, bool):
            _reject("invalid_ttl")
        if ttl < 0 or ttl > MAX_DNS_TTL_SECONDS:
            _reject("invalid_ttl")
        object.__setattr__(self, "owner", _canonical_hostname(owner))
        object.__setattr__(self, "target", _canonical_hostname(target))
        object.__setattr__(self, "ttl", ttl)


@dataclass(frozen=True, slots=True)
class FamilyResolution:
    family: AddressFamily
    terminal_owner: CanonicalHostname
    cname_chain: tuple[CNAMELink, ...]
    status: FamilyResolutionStatus
    addresses: tuple[CanonicalAddress, ...] = ()

    def __init__(
        self,
        family: AddressFamily | str,
        terminal_owner: object,
        cname_chain: Iterable[CNAMELink | tuple[object, object] | object] = (),
        status: FamilyResolutionStatus | str = FamilyResolutionStatus.ADDRESSES,
        addresses: Iterable[object] = (),
        queried_owner: object | None = None,
        owner: object | None = None,
    ) -> None:
        try:
            canonical_family = AddressFamily(family)
        except (TypeError, ValueError):
            _reject("invalid_address_family")

        canonical_owner = _canonical_hostname(terminal_owner)
        links = _normalize_cname_chain(cname_chain)
        if queried_owner is not None:
            initial_owner = _canonical_hostname(queried_owner)
        elif owner is not None:
            initial_owner = _canonical_hostname(owner)
        else:
            initial_owner = links[0].owner if links else canonical_owner
        address_items = _normalize_addresses(addresses)

        if status in (FamilyResolutionStatus.ADDRESSES, "addresses"):
            canonical_status = FamilyResolutionStatus.ADDRESSES
        elif status in (FamilyResolutionStatus.NODATA, "nodata"):
            canonical_status = FamilyResolutionStatus.NODATA
        else:
            _reject("invalid_resolution_status")

        if canonical_status is FamilyResolutionStatus.NODATA:
            if address_items:
                _reject("nodata_with_addresses")
        elif not address_items:
            _reject("empty_address_set")

        for address in address_items:
            if address.family is not canonical_family:
                _reject("address_family_mismatch")

        if not links:
            if canonical_owner != initial_owner:
                _reject("cname_terminal_mismatch")
        else:
            if links[0].owner != initial_owner:
                _reject("cname_owner_mismatch")
            if canonical_owner != links[-1].target:
                _reject("cname_terminal_mismatch")

        object.__setattr__(self, "family", canonical_family)
        object.__setattr__(self, "terminal_owner", canonical_owner)
        object.__setattr__(self, "cname_chain", links)
        object.__setattr__(self, "status", canonical_status)
        object.__setattr__(self, "addresses", address_items)


def _normalize_cname_chain(
    values: Iterable[CNAMELink | tuple[object, object] | object],
) -> tuple[CNAMELink, ...]:
    try:
        items = tuple(values)
    except TypeError:
        _reject("invalid_cname_chain")
    if len(items) > MAX_CNAME_LINKS:
        _reject("too_many_cname_links")

    links: list[CNAMELink] = []
    for item in items:
        if isinstance(item, CNAMELink):
            link = item
        elif isinstance(item, tuple) and len(item) == 2:
            link = CNAMELink(item[0], item[1])
        else:
            _reject("invalid_cname_link")
        links.append(link)

    for previous, current in zip(links, links[1:], strict=False):
        if previous.target != current.owner:
            _reject("cname_chain_disjoint")

    graph: dict[CanonicalHostname, CanonicalHostname] = {}
    for link in links:
        if link.owner in graph:
            _reject("duplicate_cname_owner")
        graph[link.owner] = link.target

    if links:
        cursor = links[0].owner
        visited: set[CanonicalHostname] = set()
        while cursor in graph:
            if cursor in visited:
                _reject("cname_cycle")
            visited.add(cursor)
            cursor = graph[cursor]
            if cursor in visited:
                _reject("cname_cycle")
    return tuple(links)


def _normalize_addresses(values: Iterable[object]) -> tuple[CanonicalAddress, ...]:
    try:
        items = tuple(values)
    except TypeError:
        _reject("invalid_address_set")
    if len(items) > MAX_TERMINAL_ADDRESSES:
        _reject("too_many_terminal_addresses")

    addresses: list[CanonicalAddress] = []
    seen: set[str] = set()
    for item in items:
        address = item if isinstance(item, CanonicalAddress) else CanonicalAddress(item)
        if address.address in seen:
            _reject("duplicate_address")
        seen.add(address.address)
        addresses.append(address)

    if addresses:
        set_result = tuple(address.address for address in addresses)
        from .ip_policy import evaluate_address_set

        classification = evaluate_address_set(set_result)
        if classification.decision is ClassificationDecision.DENY:
            _reject("prohibited_address")
    return tuple(addresses)


def _normalize_datetime(value: object, name: str) -> datetime:
    if not isinstance(value, datetime):
        _reject(f"invalid_{name}")
    if value.tzinfo is None or value.utcoffset() is None:
        _reject(f"invalid_{name}")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class ValidatedResolution:
    hostname: CanonicalHostname
    ipv4_addresses: tuple[CanonicalAddress, ...]
    ipv6_addresses: tuple[CanonicalAddress, ...]
    cname_chain: tuple[CNAMELink, ...]
    terminal_owner: CanonicalHostname
    status: ResolutionStatus
    resolved_at: datetime
    total_deadline: datetime
    policy_version: str
    a_family: FamilyResolution
    aaaa_family: FamilyResolution

    def __init__(
        self,
        hostname: object,
        ipv4_addresses: Iterable[object] = (),
        ipv6_addresses: Iterable[object] = (),
        cname_chain: Iterable[CNAMELink | tuple[object, object] | object] = (),
        terminal_owner: object | None = None,
        status: ResolutionStatus | str = ResolutionStatus.VALID,
        resolved_at: object | None = None,
        total_deadline: object | None = None,
        deadline_at: object | None = None,
        policy_version: object = POLICY_VERSION,
        family_results: Iterable[FamilyResolution] = (),
        a_family: FamilyResolution | None = None,
        aaaa_family: FamilyResolution | None = None,
    ) -> None:
        canonical_hostname = _canonical_hostname(hostname)
        ipv4 = _normalize_addresses(ipv4_addresses)
        ipv6 = _normalize_addresses(ipv6_addresses)

        for address in ipv4:
            if address.family is not AddressFamily.IPV4:
                _reject("address_family_mismatch")
        for address in ipv6:
            if address.family is not AddressFamily.IPV6:
                _reject("address_family_mismatch")

        if not ipv4 and not ipv6:
            _reject("empty_address_set")
        if len(ipv4) + len(ipv6) > MAX_TERMINAL_ADDRESSES:
            _reject("too_many_terminal_addresses")

        links = _normalize_cname_chain(cname_chain)
        canonical_terminal = (
            canonical_hostname if terminal_owner is None else _canonical_hostname(terminal_owner)
        )
        if links:
            if links[0].owner != canonical_hostname:
                _reject("cname_owner_mismatch")
            if links[-1].target != canonical_terminal:
                _reject("cname_terminal_mismatch")
        elif canonical_terminal != canonical_hostname:
            _reject("terminal_owner_mismatch")

        if status not in (
            ResolutionStatus.VALID,
            ResolutionStatus.SUCCESS,
            "valid",
        ):
            _reject("invalid_resolution_status")

        if resolved_at is None:
            _reject("missing_resolved_at")
        if total_deadline is None:
            total_deadline = deadline_at
        if total_deadline is None:
            _reject("missing_total_deadline")
        resolved = _normalize_datetime(resolved_at, "resolved_at")
        deadline = _normalize_datetime(total_deadline, "total_deadline")
        if resolved > deadline:
            _reject("deadline_before_resolution")

        if not isinstance(policy_version, str) or policy_version != POLICY_VERSION:
            _reject("invalid_policy_version")

        family_items = tuple(family_results)
        if a_family is not None:
            family_items += (a_family,)
        if aaaa_family is not None:
            family_items += (aaaa_family,)

        chains: list[tuple[CNAMELink, ...]] = []
        terminals: list[CanonicalHostname] = []
        family_by_type: dict[AddressFamily, FamilyResolution] = {}
        for family in family_items:
            if not isinstance(family, FamilyResolution):
                _reject("invalid_family_resolution")
            if family.family in family_by_type:
                _reject("duplicate_family_resolution")
            family_by_type[family.family] = family
            chains.append(family.cname_chain)
            terminals.append(family.terminal_owner)

        if len(family_items) != 2:
            _reject("missing_family_resolution")
        if set(family_by_type) != {AddressFamily.IPV4, AddressFamily.IPV6}:
            _reject("missing_family_resolution")

        a_result = family_by_type[AddressFamily.IPV4]
        aaaa_result = family_by_type[AddressFamily.IPV6]

        if a_result.status is FamilyResolutionStatus.ADDRESSES:
            if not a_result.addresses:
                _reject("empty_address_set")
            if a_result.addresses != ipv4:
                _reject("family_address_mismatch")
        else:
            if a_result.addresses:
                _reject("nodata_with_addresses")
            if ipv4:
                _reject("family_status_mismatch")

        if aaaa_result.status is FamilyResolutionStatus.ADDRESSES:
            if not aaaa_result.addresses:
                _reject("empty_address_set")
            if aaaa_result.addresses != ipv6:
                _reject("family_address_mismatch")
        else:
            if aaaa_result.addresses:
                _reject("nodata_with_addresses")
            if ipv6:
                _reject("family_status_mismatch")

        if len(set(chains)) != 1:
            _reject("cross_family_cname_mismatch")
        if len(set(terminals)) != 1:
            _reject("cross_family_terminal_mismatch")
        if chains[0] != links:
            _reject("cross_family_cname_mismatch")
        if terminals[0] != canonical_terminal:
            _reject("cross_family_terminal_mismatch")

        object.__setattr__(self, "hostname", canonical_hostname)
        object.__setattr__(self, "ipv4_addresses", ipv4)
        object.__setattr__(self, "ipv6_addresses", ipv6)
        object.__setattr__(self, "cname_chain", links)
        object.__setattr__(self, "terminal_owner", canonical_terminal)
        object.__setattr__(self, "status", ResolutionStatus.VALID)
        object.__setattr__(self, "resolved_at", resolved)
        object.__setattr__(self, "total_deadline", deadline)
        object.__setattr__(self, "policy_version", POLICY_VERSION)
        object.__setattr__(self, "a_family", a_result)
        object.__setattr__(self, "aaaa_family", aaaa_result)


IPAddressRecord = AddressRecord
