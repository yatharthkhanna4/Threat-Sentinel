"""Secure deterministic dual-stack DNS A/AAAA resolution."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import ipaddress
import time
from typing import Callable, Protocol

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.rrset
from dns.rdtypes.ANY.CNAME import CNAME

from threat_sentinel_api.modules.targets.hostname import (
    CanonicalHostname,
    canonicalize_hostname,
)

from .ip_policy import POLICY_VERSION
from .types import (
    AddressFamily,
    CanonicalAddress,
    CNAMELink,
    FamilyResolution,
    FamilyResolutionStatus,
    ValidatedResolution,
)


DNS_QUERY_TIMEOUT_SECONDS = 3.0
DNS_RESOLUTION_DEADLINE_SECONDS = 10.0
MAX_CNAME_LINKS = 8
MAX_DNS_MESSAGE_SIZE = 64 * 1024
MAX_DNS_RESOURCE_RECORDS = 128
MAX_TERMINAL_ADDRESSES = 32


class DNSAddressResolutionError(RuntimeError):
    """Generic, non-sensitive DNS A/AAAA resolution failure."""

    def __init__(self) -> None:
        super().__init__("DNS address resolution failed.")


class DNSAddressTransportError(RuntimeError):
    """Internal transport failure eligible for complete nameserver retry."""


class DNSMessageTransport(Protocol):
    def nameservers(self) -> tuple[str, ...]: ...

    def query(
        self,
        request: dns.message.Message,
        *,
        nameserver: str,
        tcp: bool,
        deadline: float,
    ) -> dns.message.Message: ...


class _SystemDNSAddressTransport:
    def __init__(self) -> None:
        self._resolver = dns.resolver.Resolver(configure=True)

    def nameservers(self) -> tuple[str, ...]:
        configured: list[str] = []
        for nameserver in self._resolver.nameservers:
            if not isinstance(nameserver, str):
                raise DNSAddressResolutionError()
            if (
                not nameserver
                or any(character.isspace() for character in nameserver)
                or any(character in nameserver for character in "/%[]")
            ):
                raise DNSAddressResolutionError()
            try:
                ipaddress.ip_address(nameserver)
            except ValueError:
                raise DNSAddressResolutionError() from None
            configured.append(nameserver)
        if not configured:
            raise DNSAddressResolutionError()
        return tuple(configured)

    def query(
        self,
        request: dns.message.Message,
        *,
        nameserver: str,
        tcp: bool,
        deadline: float,
    ) -> dns.message.Message:
        timeout = min(deadline - time.monotonic(), DNS_QUERY_TIMEOUT_SECONDS)
        if timeout <= 0:
            raise DNSAddressTransportError()
        try:
            if tcp:
                return dns.query.tcp(
                    request,
                    nameserver,
                    timeout=timeout,
                    port=self._resolver.port,
                )
            return dns.query.udp(
                request,
                nameserver,
                timeout=timeout,
                port=self._resolver.port,
            )
        except DNSAddressTransportError:
            raise
        except (dns.exception.Timeout, OSError, TimeoutError):
            raise DNSAddressTransportError() from None


class DNSAddressResolver:
    """Resolve and validate a complete dual-stack A/AAAA answer."""

    def __init__(
        self,
        transport: DNSMessageTransport | None = None,
        nameservers: tuple[str, ...] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._transport = transport if transport is not None else _SystemDNSAddressTransport()
        self._nameservers = nameservers
        self._monotonic = monotonic
        self._wall_clock = wall_clock

    def resolve(self, hostname: str) -> ValidatedResolution:
        try:
            canonical = canonicalize_hostname(hostname)
            nameservers = (
                self._nameservers
                if self._nameservers is not None
                else self._transport.nameservers()
            )
            if not nameservers:
                raise DNSAddressResolutionError()
            validated_nameservers = self._validate_nameservers(nameservers)

            start_monotonic = self._monotonic()
            overall_deadline = start_monotonic + DNS_RESOLUTION_DEADLINE_SECONDS
            resolved_wall_start = self._wall_clock()
            total_deadline_wall = resolved_wall_start + timedelta(
                seconds=DNS_RESOLUTION_DEADLINE_SECONDS
            )

            for nameserver in validated_nameservers:
                if self._monotonic() >= overall_deadline:
                    raise DNSAddressResolutionError()
                try:
                    a_result, aaaa_result = self._resolve_attempt(
                        canonical,
                        nameserver,
                        overall_deadline,
                    )
                except DNSAddressTransportError:
                    continue

                if (
                    a_result.status is FamilyResolutionStatus.NODATA
                    and aaaa_result.status is FamilyResolutionStatus.NODATA
                ):
                    raise DNSAddressResolutionError()

                if a_result.cname_chain != aaaa_result.cname_chain:
                    raise DNSAddressResolutionError()
                if a_result.terminal_owner != aaaa_result.terminal_owner:
                    raise DNSAddressResolutionError()

                ipv4 = a_result.addresses
                ipv6 = aaaa_result.addresses
                if len(ipv4) + len(ipv6) > MAX_TERMINAL_ADDRESSES:
                    raise DNSAddressResolutionError()

                return ValidatedResolution(
                    hostname=canonical,
                    ipv4_addresses=tuple(ipv4),
                    ipv6_addresses=tuple(ipv6),
                    cname_chain=a_result.cname_chain,
                    terminal_owner=a_result.terminal_owner,
                    resolved_at=self._wall_clock(),
                    total_deadline=total_deadline_wall,
                    policy_version=POLICY_VERSION,
                    family_results=(a_result, aaaa_result),
                )
            raise DNSAddressResolutionError()
        except DNSAddressResolutionError:
            raise
        except (dns.exception.DNSException, OSError, TimeoutError, ValueError):
            raise DNSAddressResolutionError() from None

    def _validate_nameservers(self, nameservers: tuple[str, ...]) -> tuple[str, ...]:
        validated: list[str] = []
        for nameserver in nameservers:
            if not isinstance(nameserver, str):
                raise DNSAddressResolutionError()
            if (
                not nameserver
                or any(character.isspace() for character in nameserver)
                or any(character in nameserver for character in "/%[]")
            ):
                raise DNSAddressResolutionError()
            try:
                ipaddress.ip_address(nameserver)
            except ValueError:
                raise DNSAddressResolutionError() from None
            validated.append(nameserver)
        return tuple(validated)

    def _resolve_attempt(
        self,
        canonical: CanonicalHostname,
        nameserver: str,
        overall_deadline: float,
    ) -> tuple[FamilyResolution, FamilyResolution]:
        a_result = self._resolve_family(
            canonical,
            dns.rdatatype.A,
            AddressFamily.IPV4,
            nameserver,
            overall_deadline,
        )
        aaaa_result = self._resolve_family(
            canonical,
            dns.rdatatype.AAAA,
            AddressFamily.IPV6,
            nameserver,
            overall_deadline,
        )
        return a_result, aaaa_result

    def _resolve_family(
        self,
        canonical: CanonicalHostname,
        record_type: dns.rdatatype.RdataType,
        family: AddressFamily,
        nameserver: str,
        overall_deadline: float,
    ) -> FamilyResolution:
        current = dns.name.from_text(f"{canonical}.", origin=dns.name.root)
        chain: list[CNAMELink] = []
        visited: set[dns.name.Name] = {current.canonicalize()}
        pending_answer: dict[dns.name.Name, list[dns.rrset.RRset]] | None = None

        while True:
            if self._monotonic() >= overall_deadline:
                raise DNSAddressResolutionError()

            if pending_answer is None:
                request = dns.message.make_query(
                    current,
                    record_type,
                    dns.rdataclass.IN,
                )
                response = self._query(
                    request,
                    nameserver,
                    tcp=False,
                    overall_deadline=overall_deadline,
                )

                if response.flags & dns.flags.TC:
                    response = self._query(
                        request,
                        nameserver,
                        tcp=True,
                        overall_deadline=overall_deadline,
                    )

                self._validate_response(response, request)
                if response.flags & dns.flags.TC:
                    raise DNSAddressResolutionError()
                if response.rcode() != dns.rcode.NOERROR:
                    raise DNSAddressResolutionError()
                rrsets = self._answer_rrsets(response.answer, record_type)
            else:
                rrsets = pending_answer
                pending_answer = None

            if not rrsets:
                return FamilyResolution(
                    family,
                    self._canonical_dns_name(current),
                    tuple(chain),
                    status=FamilyResolutionStatus.NODATA,
                    addresses=(),
                    queried_owner=canonical,
                )

            current_answer = rrsets.get(current.canonicalize())
            if current_answer is None:
                allowed_owners = {link.owner for link in chain}
                allowed_owners.update(link.target for link in chain)
                answer_owners = set(rrsets)
                if not answer_owners.issubset(allowed_owners):
                    raise DNSAddressResolutionError()
                raise DNSAddressResolutionError()

            cname_rrsets = [
                rrset
                for rrset in current_answer
                if rrset.rdtype == dns.rdatatype.CNAME
            ]
            address_rrsets = [
                rrset
                for rrset in current_answer
                if rrset.rdtype == record_type
            ]

            if cname_rrsets:
                if len(cname_rrsets) != 1 or len(address_rrsets) or len(cname_rrsets[0]) != 1:
                    raise DNSAddressResolutionError()
                if set(rrsets) - {
                    current.canonicalize(),
                    cname_rrsets[0][0].target.canonicalize(),
                }:
                    raise DNSAddressResolutionError()
                cname_record = next(iter(cname_rrsets[0]))
                if not isinstance(cname_record, CNAME):
                    raise DNSAddressResolutionError()
                target = cname_record.target.canonicalize()
                target_hostname = self._canonical_dns_name(target)
                link = CNAMELink(self._canonical_dns_name(current), target_hostname)
                if len(chain) >= MAX_CNAME_LINKS:
                    raise DNSAddressResolutionError()
                if target == dns.name.root or target in visited:
                    raise DNSAddressResolutionError()
                for previous in chain:
                    if previous.target == target_hostname and previous.owner == link.owner:
                        raise DNSAddressResolutionError()
                chain.append(link)
                visited.add(target)
                current = target
                if target in rrsets:
                    pending_answer = {target: rrsets[target]}
                continue

            if address_rrsets:
                if len(address_rrsets) != 1:
                    raise DNSAddressResolutionError()
                if set(rrsets) != {current.canonicalize()}:
                    raise DNSAddressResolutionError()
                rrset = address_rrsets[0]
                if rrset.rdclass != dns.rdataclass.IN:
                    raise DNSAddressResolutionError()
                if len(rrset) == 0 or len(rrset) > MAX_TERMINAL_ADDRESSES:
                    raise DNSAddressResolutionError()

                addresses: list[CanonicalAddress] = []
                seen: set[str] = set()
                for record in rrset:
                    try:
                        text = record.to_text()
                        parsed = ipaddress.ip_address(text)
                    except (ValueError, AttributeError):
                        raise DNSAddressResolutionError() from None
                    if record_type == dns.rdatatype.A and parsed.version != 4:
                        raise DNSAddressResolutionError()
                    if record_type == dns.rdatatype.AAAA and parsed.version != 6:
                        raise DNSAddressResolutionError()
                    canonical_address = parsed.compressed
                    if canonical_address in seen:
                        raise DNSAddressResolutionError()
                    seen.add(canonical_address)
                    addresses.append(CanonicalAddress(canonical_address))

                terminal_owner = self._canonical_dns_name(current)
                return FamilyResolution(
                    family,
                    terminal_owner,
                    tuple(chain),
                    status=FamilyResolutionStatus.ADDRESSES,
                    addresses=tuple(addresses),
                    queried_owner=canonical,
                )

            raise DNSAddressResolutionError()

    def _query(
        self,
        request: dns.message.Message,
        nameserver: str,
        *,
        tcp: bool,
        overall_deadline: float,
    ) -> dns.message.Message:
        query_start = self._monotonic()
        if query_start >= overall_deadline:
            raise DNSAddressResolutionError()
        query_deadline = min(
            overall_deadline,
            query_start + DNS_QUERY_TIMEOUT_SECONDS,
        )
        response = self._transport.query(
            request,
            nameserver=nameserver,
            tcp=tcp,
            deadline=query_deadline,
        )
        query_finish = self._monotonic()
        if query_finish >= query_deadline or query_finish >= overall_deadline:
            raise DNSAddressResolutionError()
        return response

    def _answer_rrsets(
        self,
        rrsets: list[dns.rrset.RRset],
        record_type: dns.rdatatype.RdataType,
    ) -> dict[dns.name.Name, list[dns.rrset.RRset]]:
        grouped: dict[dns.name.Name, list[dns.rrset.RRset]] = {}
        seen_types: set[tuple[dns.name.Name, dns.rdatatype.RdataType]] = set()
        for rrset in rrsets:
            if rrset.rdclass != dns.rdataclass.IN:
                raise DNSAddressResolutionError()
            allowed_types = {
                dns.rdatatype.CNAME,
                record_type,
            }
            if rrset.rdtype not in allowed_types:
                raise DNSAddressResolutionError()
            key = (rrset.name.canonicalize(), rrset.rdtype)
            if key in seen_types:
                raise DNSAddressResolutionError()
            seen_types.add(key)
            grouped.setdefault(rrset.name.canonicalize(), []).append(rrset)
        return grouped

    def _validate_response(
        self,
        response: dns.message.Message,
        request: dns.message.Message,
    ) -> None:
        try:
            wire_size = len(response.to_wire())
        except (dns.exception.DNSException, ValueError):
            raise DNSAddressResolutionError() from None

        # Bound all wire sections, but only answer records can affect resolution.
        sections = (response.answer, response.authority, response.additional)
        record_count = sum(len(rrset) for section in sections for rrset in section)
        if wire_size > MAX_DNS_MESSAGE_SIZE or record_count > MAX_DNS_RESOURCE_RECORDS:
            raise DNSAddressResolutionError()
        if (
            response.id != request.id
            or not response.flags & dns.flags.QR
            or response.opcode() != dns.opcode.QUERY
            or response.rcode() not in {
                dns.rcode.NOERROR,
                dns.rcode.NXDOMAIN,
                dns.rcode.SERVFAIL,
                dns.rcode.REFUSED,
            }
            or len(response.question) != 1
        ):
            raise DNSAddressResolutionError()

        response_question = response.question[0]
        request_question = request.question[0]
        if (
            response_question.name.canonicalize()
            != request_question.name.canonicalize()
            or response_question.rdtype != request_question.rdtype
            or response_question.rdclass != request_question.rdclass
        ):
            raise DNSAddressResolutionError()

    @staticmethod
    def _canonical_dns_name(name: dns.name.Name) -> CanonicalHostname:
        if not name.is_absolute() or name == dns.name.root:
            raise DNSAddressResolutionError()
        canonical = name.canonicalize().to_text()
        try:
            return canonicalize_hostname(
                canonical[:-1] if canonical.endswith(".") else canonical
            )
        except ValueError:
            raise DNSAddressResolutionError() from None
