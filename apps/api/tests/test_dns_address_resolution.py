from collections.abc import Callable
from datetime import UTC, datetime
import dns.exception
import dns.flags
import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.rcode
import pytest

from threat_sentinel_api.modules.networking.dns_address import (
    DNSAddressResolutionError,
    DNSAddressResolver,
    DNSAddressTransportError,
    MAX_CNAME_LINKS,
    _SystemDNSAddressTransport,
)


class FixtureTransport:
    def __init__(
        self,
        nameservers: tuple[str, ...],
        responder: Callable[[dns.message.Message, str, bool], dns.message.Message | Exception],
    ) -> None:
        self._nameservers = nameservers
        self.responder = responder
        self.requests: list[tuple[dns.message.Message, str, bool]] = []
        self.deadlines: list[float] = []

    def nameservers(self) -> tuple[str, ...]:
        return self._nameservers

    def query(
        self,
        request: dns.message.Message,
        *,
        nameserver: str,
        tcp: bool,
        deadline: float,
    ) -> dns.message.Message:
        self.requests.append((request, nameserver, tcp))
        self.deadlines.append(deadline)
        result = self.responder(request, nameserver, tcp)
        if isinstance(result, Exception):
            raise result
        return result


def answer(request: dns.message.Message, rdtype: str, *addresses: str) -> dns.message.Message:
    response = dns.message.make_response(request)
    response.answer.append(
        dns.rrset.from_text(
            request.question[0].name,
            60,
            "IN",
            rdtype,
            *addresses,
        )
    )
    return response


def nodata(request: dns.message.Message) -> dns.message.Message:
    return dns.message.make_response(request)


def cname(request: dns.message.Message, target: str) -> dns.message.Message:
    response = dns.message.make_response(request)
    response.answer.append(
        dns.rrset.from_text(
            request.question[0].name,
            60,
            "IN",
            "CNAME",
            target,
        )
    )
    return response


def _sequential_cname_responder(
    link_count: int,
    queries: list[tuple[str, int]],
    links: list[tuple[str, str]],
) -> Callable[[dns.message.Message, str, bool], dns.message.Message]:
    def respond(
        request: dns.message.Message,
        nameserver: str,
        tcp: bool,
    ) -> dns.message.Message:
        del nameserver, tcp
        owner = request.question[0].name.to_text()
        record_type = request.question[0].rdtype
        queries.append((owner, record_type))
        target_index = (
            0
            if owner == "example.com."
            else int(owner.removeprefix("link-").removesuffix(".example.net.")) + 1
        )
        if target_index < link_count:
            target = f"link-{target_index}.example.net."
            links.append((owner, target))
            return cname(request, target)
        if record_type == dns.rdatatype.A:
            return answer(request, "A", "8.8.8.8")
        return answer(request, "AAAA", "2001:4860:4860::8888")

    return respond


def protocol_response(
    request: dns.message.Message,
    rcode: dns.rcode.Rcode,
) -> dns.message.Message:
    response = dns.message.make_response(request)
    response.set_rcode(rcode)
    return response


def dual_responder(
    a_addresses: tuple[str, ...] = ("8.8.8.8",),
    aaaa_addresses: tuple[str, ...] = ("2001:4860:4860::8888",),
) -> Callable[[dns.message.Message, str, bool], dns.message.Message]:
    def respond(
        request: dns.message.Message,
        nameserver: str,
        tcp: bool,
    ) -> dns.message.Message:
        del nameserver, tcp
        if request.question[0].rdtype == dns.rdatatype.A:
            return answer(request, "A", *a_addresses) if a_addresses else nodata(request)
        return (
            answer(request, "AAAA", *aaaa_addresses)
            if aaaa_addresses
            else nodata(request)
        )

    return respond


def test_successful_dual_stack_resolution() -> None:
    transport = FixtureTransport(
        ("192.0.2.53",),
        dual_responder(
            ("8.8.8.8", "1.1.1.1"),
            ("2001:4860:4860::8888", "2606:4700:4700::1111"),
        ),
    )
    result = DNSAddressResolver(transport=transport).resolve("Example.COM.")

    assert result.hostname == "example.com"
    assert tuple(address.address for address in result.ipv4_addresses) == ("8.8.8.8", "1.1.1.1")
    assert tuple(address.address for address in result.ipv6_addresses) == (
        "2001:4860:4860::8888",
        "2606:4700:4700::1111",
    )
    assert result.a_family.status.value == "addresses"
    assert result.aaaa_family.status.value == "addresses"
    assert result.policy_version == "1.0.0"


def test_a_only_and_aaaa_only_results() -> None:
    a_only = DNSAddressResolver(
        transport=FixtureTransport(("192.0.2.53",), dual_responder(("8.8.8.8",), ()))
    ).resolve("example.com")
    aaaa_only = DNSAddressResolver(
        transport=FixtureTransport(
            ("192.0.2.53",),
            dual_responder((), ("2001:4860:4860::8888",)),
        )
    ).resolve("example.com")

    assert a_only.a_family.status.value == "addresses"
    assert a_only.aaaa_family.status.value == "nodata"
    assert aaaa_only.a_family.status.value == "nodata"
    assert aaaa_only.aaaa_family.status.value == "addresses"


@pytest.mark.parametrize("rcode", [dns.rcode.NXDOMAIN, dns.rcode.SERVFAIL, dns.rcode.REFUSED])
def test_completed_protocol_outcomes_do_not_fallback(rcode: dns.rcode.Rcode) -> None:
    calls: list[str] = []

    def respond(
        request: dns.message.Message,
        nameserver: str,
        tcp: bool,
    ) -> dns.message.Message:
        del tcp
        calls.append(nameserver)
        return protocol_response(request, rcode)

    transport = FixtureTransport(("192.0.2.53", "192.0.2.54"), respond)
    with pytest.raises(DNSAddressResolutionError):
        DNSAddressResolver(transport=transport).resolve("example.com")
    assert calls == ["192.0.2.53"]


def test_aaaa_protocol_failure_does_not_fallback_after_a_successful_a_answer() -> None:
    calls: list[tuple[str, int]] = []

    def respond(
        request: dns.message.Message,
        nameserver: str,
        tcp: bool,
    ) -> dns.message.Message:
        del tcp
        record_type = request.question[0].rdtype
        calls.append((nameserver, record_type))
        if record_type == dns.rdatatype.A:
            return answer(request, "A", "8.8.8.8")
        return protocol_response(request, dns.rcode.SERVFAIL)

    transport = FixtureTransport(("192.0.2.53", "192.0.2.54"), respond)

    with pytest.raises(DNSAddressResolutionError):
        DNSAddressResolver(transport=transport).resolve("example.com")

    assert calls == [
        ("192.0.2.53", dns.rdatatype.A),
        ("192.0.2.53", dns.rdatatype.AAAA),
    ]


def test_both_nodata_fails() -> None:
    transport = FixtureTransport(
        ("192.0.2.53",),
        dual_responder((), ()),
    )
    with pytest.raises(DNSAddressResolutionError):
        DNSAddressResolver(transport=transport).resolve("example.com")


def test_cname_continuation_uses_same_nameserver() -> None:
    queried: list[tuple[str, str, bool]] = []

    def respond(
        request: dns.message.Message,
        nameserver: str,
        tcp: bool,
    ) -> dns.message.Message:
        owner = request.question[0].name.to_text()
        rdtype = request.question[0].rdtype
        queried.append((nameserver, owner, tcp))
        if owner == "example.com.":
            return cname(request, "alias.example.net.")
        if rdtype == dns.rdatatype.A:
            return answer(request, "A", "8.8.8.8")
        return answer(request, "AAAA", "2001:4860:4860::8888")

    transport = FixtureTransport(("192.0.2.53", "192.0.2.54"), respond)
    result = DNSAddressResolver(transport=transport).resolve("example.com")

    assert all(nameserver == "192.0.2.53" for nameserver, _, _ in queried)
    assert len({nameserver for nameserver, _, _ in queried}) == 1
    assert result.cname_chain[0].owner == "example.com"
    assert result.cname_chain[0].target == "alias.example.net"
    assert result.terminal_owner == "alias.example.net"


def test_cname_chain_in_response_is_followed_without_extra_query() -> None:
    def respond(
        request: dns.message.Message,
        nameserver: str,
        tcp: bool,
    ) -> dns.message.Message:
        del nameserver, tcp
        rdtype = "A" if request.question[0].rdtype == dns.rdatatype.A else "AAAA"
        address = "8.8.8.8" if rdtype == "A" else "2001:4860:4860::8888"
        response = dns.message.make_response(request)
        response.answer.append(
            dns.rrset.from_text(
                "example.com.",
                60,
                "IN",
                "CNAME",
                "alias.example.net.",
            )
        )
        response.answer.append(
            dns.rrset.from_text(
                "alias.example.net.",
                60,
                "IN",
                rdtype,
                address,
            )
        )
        return response

    transport = FixtureTransport(("192.0.2.53",), respond)
    result = DNSAddressResolver(transport=transport).resolve("example.com")
    assert result.cname_chain[0].target == "alias.example.net"


@pytest.mark.parametrize("kind", ["cycle", "disjoint"])
def test_malformed_cname_chains_fail(kind: str) -> None:
    def respond(
        request: dns.message.Message,
        nameserver: str,
        tcp: bool,
    ) -> dns.message.Message:
        del nameserver, tcp
        if kind == "cycle":
            target = "example.com."
        else:
            target = "one.example.net."
        return cname(request, target)

    transport = FixtureTransport(("192.0.2.53",), respond)
    with pytest.raises(DNSAddressResolutionError):
        DNSAddressResolver(transport=transport).resolve("example.com")


def test_cname_chain_at_configured_limit_is_resolved() -> None:
    queries: list[tuple[str, int]] = []
    links: list[tuple[str, str]] = []
    expected_links = [
        ("example.com.", "link-0.example.net."),
        *[
            (f"link-{index}.example.net.", f"link-{index + 1}.example.net.")
            for index in range(MAX_CNAME_LINKS - 1)
        ],
    ]
    expected_owners = [owner for owner, _ in expected_links] + [
        expected_links[-1][1]
    ]
    transport = FixtureTransport(
        ("192.0.2.53",),
        _sequential_cname_responder(MAX_CNAME_LINKS, queries, links),
    )

    result = DNSAddressResolver(transport=transport).resolve("example.com")

    assert len(result.cname_chain) == MAX_CNAME_LINKS
    assert result.terminal_owner == f"link-{MAX_CNAME_LINKS - 1}.example.net"
    assert links == expected_links * 2
    assert queries == [
        *((owner, dns.rdatatype.A) for owner in expected_owners),
        *((owner, dns.rdatatype.AAAA) for owner in expected_owners),
    ]


def test_cname_chain_one_over_configured_limit_fails_with_distinct_links() -> None:
    queries: list[tuple[str, int]] = []
    links: list[tuple[str, str]] = []
    expected_links = [
        ("example.com.", "link-0.example.net."),
        *[
            (f"link-{index}.example.net.", f"link-{index + 1}.example.net.")
            for index in range(MAX_CNAME_LINKS)
        ],
    ]
    transport = FixtureTransport(
        ("192.0.2.53",),
        _sequential_cname_responder(MAX_CNAME_LINKS + 1, queries, links),
    )

    with pytest.raises(DNSAddressResolutionError):
        DNSAddressResolver(transport=transport).resolve("example.com")

    assert links == expected_links
    assert len({owner for owner, _ in links}) == MAX_CNAME_LINKS + 1
    assert queries == [
        (owner, dns.rdatatype.A)
        for owner, _ in expected_links
    ]


def test_different_cname_chains_across_families_fail() -> None:
    def respond(
        request: dns.message.Message,
        nameserver: str,
        tcp: bool,
    ) -> dns.message.Message:
        del nameserver, tcp
        if request.question[0].rdtype == dns.rdatatype.A:
            return cname(request, "a.example.net.")
        return cname(request, "aaaa.example.net.")

    transport = FixtureTransport(("192.0.2.53",), respond)
    with pytest.raises(DNSAddressResolutionError):
        DNSAddressResolver(transport=transport).resolve("example.com")


def test_mismatched_transaction_and_question_fail() -> None:
    calls: list[str] = []

    def mismatched_id(
        request: dns.message.Message,
        nameserver: str,
        tcp: bool,
    ) -> dns.message.Message:
        del tcp
        calls.append(nameserver)
        response = answer(request, "A", "8.8.8.8")
        response.id = (response.id + 1) % 65536
        return response

    transport = FixtureTransport(("192.0.2.53", "192.0.2.54"), mismatched_id)
    with pytest.raises(DNSAddressResolutionError):
        DNSAddressResolver(transport=transport).resolve("example.com")
    assert calls == ["192.0.2.53"]


def test_mismatched_question_fails() -> None:
    calls: list[str] = []

    def mismatched(request: dns.message.Message, nameserver: str, tcp: bool) -> dns.message.Message:
        del tcp
        calls.append(nameserver)
        response = dns.message.make_response(request)
        response.question = dns.message.make_query(
            "other.example.",
            dns.rdatatype.A,
            dns.rdataclass.IN,
        ).question
        return response

    transport = FixtureTransport(("192.0.2.53", "192.0.2.54"), mismatched)
    with pytest.raises(DNSAddressResolutionError):
        DNSAddressResolver(transport=transport).resolve("example.com")
    assert calls == ["192.0.2.53"]


def test_system_transport_udp_timeout_restarts_complete_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, int]] = []

    def udp(
        request: dns.message.Message,
        nameserver: str,
        *,
        timeout: float,
        port: int,
    ) -> dns.message.Message:
        del timeout, port
        calls.append((nameserver, request.question[0].rdtype))
        if nameserver == "192.0.2.53":
            raise dns.exception.Timeout
        rdtype = "A" if request.question[0].rdtype == dns.rdatatype.A else "AAAA"
        address = "8.8.8.8" if rdtype == "A" else "2001:4860:4860::8888"
        return answer(request, rdtype, address)

    monkeypatch.setattr(dns.query, "udp", udp)
    transport = _SystemDNSAddressTransport()
    result = DNSAddressResolver(
        transport=transport,
        nameservers=("192.0.2.53", "192.0.2.54"),
    ).resolve("example.com")

    assert calls[:2] == [
        ("192.0.2.53", dns.rdatatype.A),
        ("192.0.2.54", dns.rdatatype.A),
    ]
    assert all(nameserver == "192.0.2.54" for nameserver, _ in calls[1:])
    assert result.ipv4_addresses[0].address == "8.8.8.8"


def test_aaaa_transport_failure_restarts_complete_dual_stack_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, int]] = []

    def udp(
        request: dns.message.Message,
        nameserver: str,
        *,
        timeout: float,
        port: int,
    ) -> dns.message.Message:
        del timeout, port
        record_type = request.question[0].rdtype
        calls.append((nameserver, record_type))
        if nameserver == "192.0.2.53" and record_type == dns.rdatatype.AAAA:
            raise OSError("AAAA transport failed")
        if record_type == dns.rdatatype.A:
            address = "8.8.8.8" if nameserver == "192.0.2.53" else "1.1.1.1"
            return answer(request, "A", address)
        return answer(request, "AAAA", "2606:4700:4700::1111")

    monkeypatch.setattr(dns.query, "udp", udp)
    transport = _SystemDNSAddressTransport()
    result = DNSAddressResolver(
        transport=transport,
        nameservers=("192.0.2.53", "192.0.2.54"),
    ).resolve("example.com")

    assert calls == [
        ("192.0.2.53", dns.rdatatype.A),
        ("192.0.2.53", dns.rdatatype.AAAA),
        ("192.0.2.54", dns.rdatatype.A),
        ("192.0.2.54", dns.rdatatype.AAAA),
    ]
    assert tuple(address.address for address in result.ipv4_addresses) == ("1.1.1.1",)
    assert tuple(address.address for address in result.ipv6_addresses) == (
        "2606:4700:4700::1111",
    )
    assert result.a_family.addresses == result.ipv4_addresses
    assert result.aaaa_family.addresses == result.ipv6_addresses


def test_system_transport_tcp_failure_restarts_complete_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, int, bool]] = []

    def udp(
        request: dns.message.Message,
        nameserver: str,
        *,
        timeout: float,
        port: int,
    ) -> dns.message.Message:
        del timeout, port
        calls.append((nameserver, request.question[0].rdtype, False))
        if nameserver == "192.0.2.53":
            truncated = dns.message.make_response(request)
            truncated.flags |= dns.flags.TC
            return truncated
        rdtype = "A" if request.question[0].rdtype == dns.rdatatype.A else "AAAA"
        address = "8.8.8.8" if rdtype == "A" else "2001:4860:4860::8888"
        return answer(request, rdtype, address)

    def tcp(
        request: dns.message.Message,
        nameserver: str,
        *,
        timeout: float,
        port: int,
    ) -> dns.message.Message:
        del timeout, port
        calls.append((nameserver, request.question[0].rdtype, True))
        raise OSError("TCP connection failed")

    monkeypatch.setattr(dns.query, "udp", udp)
    monkeypatch.setattr(dns.query, "tcp", tcp)
    transport = _SystemDNSAddressTransport()
    result = DNSAddressResolver(
        transport=transport,
        nameservers=("192.0.2.53", "192.0.2.54"),
    ).resolve("example.com")

    assert calls[:2] == [
        ("192.0.2.53", dns.rdatatype.A, False),
        ("192.0.2.53", dns.rdatatype.A, True),
    ]
    assert ("192.0.2.54", dns.rdatatype.A, False) in calls
    assert result.ipv4_addresses[0].address == "8.8.8.8"


def test_malformed_udp_response_does_not_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def udp(
        request: dns.message.Message,
        nameserver: str,
        *,
        timeout: float,
        port: int,
    ) -> dns.message.Message:
        del request, timeout, port
        calls.append(nameserver)
        raise dns.exception.FormError

    monkeypatch.setattr(dns.query, "udp", udp)
    transport = _SystemDNSAddressTransport()
    with pytest.raises(DNSAddressResolutionError):
        DNSAddressResolver(
            transport=transport,
            nameservers=("192.0.2.53", "192.0.2.54"),
        ).resolve("example.com")
    assert calls == ["192.0.2.53"]


def test_malformed_tcp_response_after_truncation_does_not_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, bool]] = []

    def udp(
        request: dns.message.Message,
        nameserver: str,
        *,
        timeout: float,
        port: int,
    ) -> dns.message.Message:
        del timeout, port
        calls.append((nameserver, False))
        response = dns.message.make_response(request)
        response.flags |= dns.flags.TC
        return response

    def tcp(
        request: dns.message.Message,
        nameserver: str,
        *,
        timeout: float,
        port: int,
    ) -> dns.message.Message:
        del request, timeout, port
        calls.append((nameserver, True))
        raise dns.exception.FormError

    monkeypatch.setattr(dns.query, "udp", udp)
    monkeypatch.setattr(dns.query, "tcp", tcp)
    transport = _SystemDNSAddressTransport()
    with pytest.raises(DNSAddressResolutionError):
        DNSAddressResolver(
            transport=transport,
            nameservers=("192.0.2.53", "192.0.2.54"),
        ).resolve("example.com")
    assert calls == [("192.0.2.53", False), ("192.0.2.53", True)]


def test_udp_truncation_uses_one_tcp_retry_same_nameserver() -> None:
    calls: list[tuple[str, bool]] = []

    def respond(
        request: dns.message.Message,
        nameserver: str,
        tcp: bool,
    ) -> dns.message.Message:
        calls.append((nameserver, tcp))
        rdtype = "A" if request.question[0].rdtype == dns.rdatatype.A else "AAAA"
        address = "8.8.8.8" if rdtype == "A" else "2001:4860:4860::8888"
        if not tcp:
            truncated = dns.message.make_response(request)
            truncated.flags |= dns.flags.TC
            return truncated
        return answer(request, rdtype, address)

    transport = FixtureTransport(("192.0.2.53", "192.0.2.54"), respond)
    result = DNSAddressResolver(transport=transport).resolve("example.com")
    tcp_calls = [call for call in calls if call[1]]
    assert len(tcp_calls) == 2
    assert all(call == ("192.0.2.53", True) for call in tcp_calls)
    assert result.a_family.status.value == "addresses"


def test_tcp_transport_failure_restarts_complete_attempt_on_next_nameserver() -> None:
    calls: list[tuple[str, str, bool]] = []

    def respond(
        request: dns.message.Message,
        nameserver: str,
        tcp: bool,
    ) -> dns.message.Message:
        owner = request.question[0].name.to_text()
        calls.append((nameserver, owner, tcp))
        if nameserver == "192.0.2.53" and not tcp:
            truncated = dns.message.make_response(request)
            truncated.flags |= dns.flags.TC
            return truncated
        if nameserver == "192.0.2.53" and tcp:
            raise DNSAddressTransportError()
        rdtype = "A" if request.question[0].rdtype == dns.rdatatype.A else "AAAA"
        address = "8.8.8.8" if rdtype == "A" else "2001:4860:4860::8888"
        return answer(request, rdtype, address)

    transport = FixtureTransport(("192.0.2.53", "192.0.2.54"), respond)
    result = DNSAddressResolver(transport=transport).resolve("example.com")
    assert result.a_family.status.value == "addresses"
    assert any(call[0] == "192.0.2.54" for call in calls)


def test_udp_transport_failure_restarts_on_next_nameserver_without_combining() -> None:
    calls: list[tuple[str, str]] = []

    def respond(
        request: dns.message.Message,
        nameserver: str,
        tcp: bool,
    ) -> dns.message.Message:
        del tcp
        calls.append((nameserver, request.question[0].name.to_text()))
        if nameserver == "192.0.2.53":
            raise DNSAddressTransportError()
        rdtype = "A" if request.question[0].rdtype == dns.rdatatype.A else "AAAA"
        address = "8.8.8.8" if rdtype == "A" else "2001:4860:4860::8888"
        return answer(request, rdtype, address)

    transport = FixtureTransport(("192.0.2.53", "192.0.2.54"), respond)
    result = DNSAddressResolver(transport=transport).resolve("example.com")
    assert calls[0][0] == "192.0.2.53"
    assert all(call[0] == "192.0.2.54" for call in calls[1:])
    assert result.ipv4_addresses[0].address == "8.8.8.8"


@pytest.mark.parametrize(
    "address",
    [
        "10.0.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.1",
        "::1",
        "::ffff:8.8.8.8",
        "64:ff9b::808:808",
        "2001:db8::1",
    ],
)
def test_prohibited_addresses_are_rejected(address: str) -> None:
    rdtype = "A" if ":" not in address else "AAAA"
    rdtype_value = dns.rdatatype.A if rdtype == "A" else dns.rdatatype.AAAA
    transport = FixtureTransport(
        ("192.0.2.53",),
        lambda request, _ns, _tcp: (
            answer(request, rdtype, address)
            if request.question[0].rdtype == rdtype_value
            else nodata(request)
        ),
    )
    with pytest.raises(DNSAddressResolutionError):
        DNSAddressResolver(transport=transport).resolve("example.com")


def test_mixed_allowed_and_prohibited_answers_are_rejected() -> None:
    def respond(
        request: dns.message.Message,
        nameserver: str,
        tcp: bool,
    ) -> dns.message.Message:
        del nameserver, tcp
        if request.question[0].rdtype == dns.rdatatype.A:
            return answer(request, "A", "8.8.8.8", "10.0.0.1")
        return answer(request, "AAAA", "2001:4860:4860::8888")

    transport = FixtureTransport(("192.0.2.53",), respond)
    with pytest.raises(DNSAddressResolutionError):
        DNSAddressResolver(transport=transport).resolve("example.com")


def test_terminal_address_count_boundary() -> None:
    addresses = [f"8.8.{index // 256}.{index % 256}" for index in range(32)]
    transport = FixtureTransport(
        ("192.0.2.53",),
        lambda request, _ns, _tcp: (
            answer(request, "A", *addresses)
            if request.question[0].rdtype == dns.rdatatype.A
            else nodata(request)
        ),
    )
    result = DNSAddressResolver(transport=transport).resolve("example.com")
    assert len(result.ipv4_addresses) == 32


def test_terminal_address_count_over_boundary_is_rejected() -> None:
    addresses = [f"8.8.{index // 256}.{index % 256}" for index in range(33)]
    transport = FixtureTransport(
        ("192.0.2.53",),
        lambda request, _ns, _tcp: (
            answer(request, "A", *addresses)
            if request.question[0].rdtype == dns.rdatatype.A
            else nodata(request)
        ),
    )
    with pytest.raises(DNSAddressResolutionError):
        DNSAddressResolver(transport=transport).resolve("example.com")


def _response_with_txt_padding(
    request: dns.message.Message,
    payload_size: int,
) -> dns.message.Message:
    response = answer(request, "A", "8.8.8.8")
    parts = [
        "a" * min(255, payload_size - offset)
        for offset in range(0, payload_size, 255)
    ]
    text = " ".join(f'"{part}"' for part in parts)
    response.additional.append(
        dns.rrset.from_text("padding.example.", 60, "IN", "TXT", text)
    )
    return response


def test_maximum_representable_dns_message_size_is_accepted() -> None:
    def sized_response(
        request: dns.message.Message,
        nameserver: str,
        tcp: bool,
    ) -> dns.message.Message:
        del nameserver, tcp
        if request.question[0].rdtype == dns.rdatatype.AAAA:
            return nodata(request)
        response = _response_with_txt_padding(request, 65207)
        assert len(response.to_wire()) == 65535
        return response

    transport = FixtureTransport(("192.0.2.53",), sized_response)
    result = DNSAddressResolver(transport=transport).resolve("example.com")
    assert result.ipv4_addresses[0].address == "8.8.8.8"


def test_dns_message_that_exceeds_wire_size_limit_is_rejected() -> None:
    def oversize(
        request: dns.message.Message,
        nameserver: str,
        tcp: bool,
    ) -> dns.message.Message:
        del nameserver, tcp
        return _response_with_txt_padding(request, 65208)

    transport = FixtureTransport(("192.0.2.53",), oversize)
    with pytest.raises(DNSAddressResolutionError):
        DNSAddressResolver(transport=transport).resolve("example.com")


@pytest.mark.parametrize("section", ["authority", "additional"])
def test_non_answer_address_records_are_not_terminal_addresses(section: str) -> None:
    def respond(
        request: dns.message.Message,
        nameserver: str,
        tcp: bool,
    ) -> dns.message.Message:
        del nameserver, tcp
        if request.question[0].rdtype == dns.rdatatype.AAAA:
            return answer(request, "AAAA", "2001:4860:4860::8888")
        response = dns.message.make_response(request)
        getattr(response, section).append(
            dns.rrset.from_text("example.com.", 60, "IN", "A", "8.8.8.8")
        )
        return response

    transport = FixtureTransport(("192.0.2.53",), respond)
    result = DNSAddressResolver(transport=transport).resolve("example.com")
    assert result.a_family.status.value == "nodata"
    assert result.ipv4_addresses == ()
    assert result.ipv6_addresses[0].address == "2001:4860:4860::8888"


def test_authority_soa_is_valid_for_nodata() -> None:
    def respond(
        request: dns.message.Message,
        nameserver: str,
        tcp: bool,
    ) -> dns.message.Message:
        del nameserver, tcp
        if request.question[0].rdtype == dns.rdatatype.AAAA:
            return answer(request, "AAAA", "2001:4860:4860::8888")
        response = dns.message.make_response(request)
        response.authority.append(
            dns.rrset.from_text(
                "example.com.",
                60,
                "IN",
                "SOA",
                "ns.example.com. hostmaster.example.com. 1 3600 600 86400 60",
            )
        )
        return response

    transport = FixtureTransport(("192.0.2.53",), respond)
    result = DNSAddressResolver(transport=transport).resolve("example.com")
    assert result.a_family.status.value == "nodata"
    assert result.ipv4_addresses == ()


def test_record_count_boundary_rejects_129_records() -> None:
    def many_records(
        request: dns.message.Message,
        nameserver: str,
        tcp: bool,
    ) -> dns.message.Message:
        del nameserver, tcp
        response = dns.message.make_response(request)
        for index in range(129):
            response.answer.append(
                dns.rrset.from_text(
                    f"record-{index}.example.",
                    60,
                    "IN",
                    "A",
                    "8.8.8.8",
                )
            )
        return response

    transport = FixtureTransport(("192.0.2.53",), many_records)
    with pytest.raises(DNSAddressResolutionError):
        DNSAddressResolver(transport=transport).resolve("example.com")


def test_record_count_accepts_128_records() -> None:
    def many_records(
        request: dns.message.Message,
        nameserver: str,
        tcp: bool,
    ) -> dns.message.Message:
        del nameserver, tcp
        response = answer(request, "A", "8.8.8.8")
        for index in range(127):
            response.additional.append(
                dns.rrset.from_text(
                    f"record-{index}.example.",
                    60,
                    "IN",
                    "A",
                    "8.8.8.8",
                )
            )
        return response

    transport = FixtureTransport(("192.0.2.53",), many_records)
    def aaaa_nodata(
        request: dns.message.Message,
        nameserver: str,
        tcp: bool,
    ) -> dns.message.Message:
        del nameserver, tcp
        return nodata(request)

    transport.responder = lambda request, nameserver, tcp: (
        many_records(request, nameserver, tcp)
        if request.question[0].rdtype == dns.rdatatype.A
        else aaaa_nodata(request, nameserver, tcp)
    )
    result = DNSAddressResolver(transport=transport).resolve("example.com")
    assert result.a_family.status.value == "addresses"


def test_query_deadlines_are_bounded_by_original_overall_deadline() -> None:
    now = [100.0]
    query_starts: list[float] = []

    def monotonic() -> float:
        return now[0]

    def respond(
        request: dns.message.Message,
        nameserver: str,
        tcp: bool,
    ) -> dns.message.Message:
        del nameserver, tcp
        query_starts.append(now[0])
        owner = request.question[0].name.to_text()
        if owner == "example.com.":
            response = cname(request, "alias.example.net.")
        elif request.question[0].rdtype == dns.rdatatype.A:
            response = answer(request, "A", "8.8.8.8")
        else:
            response = answer(request, "AAAA", "2001:4860:4860::8888")
        now[0] += 2.5 if len(query_starts) < 4 else 1.5
        return response

    transport = FixtureTransport(("192.0.2.53",), respond)
    result = DNSAddressResolver(
        transport=transport,
        monotonic=monotonic,
        wall_clock=lambda: datetime(2026, 11, 24, tzinfo=UTC),
    ).resolve("example.com")
    assert result.total_deadline > result.resolved_at
    assert query_starts == [100.0, 102.5, 105.0, 107.5]
    assert transport.deadlines == [103.0, 105.5, 108.0, 110.0]
    assert all(
        deadline <= start + 3.0
        for start, deadline in zip(query_starts, transport.deadlines, strict=True)
    )
    assert all(deadline <= 110.0 for deadline in transport.deadlines)


def test_response_returned_after_query_deadline_is_rejected() -> None:
    now = [100.0]

    def respond(
        request: dns.message.Message,
        nameserver: str,
        tcp: bool,
    ) -> dns.message.Message:
        del nameserver, tcp
        now[0] = 103.01
        rdtype = "A" if request.question[0].rdtype == dns.rdatatype.A else "AAAA"
        address = "8.8.8.8" if rdtype == "A" else "2001:4860:4860::8888"
        return answer(request, rdtype, address)

    transport = FixtureTransport(("192.0.2.53", "192.0.2.54"), respond)
    with pytest.raises(DNSAddressResolutionError):
        DNSAddressResolver(
            transport=transport,
            monotonic=lambda: now[0],
        ).resolve("example.com")
    assert transport.deadlines == [103.0]
    assert len(transport.requests) == 1


def test_late_final_aaaa_response_after_overall_deadline_is_rejected() -> None:
    now = [100.0]
    query_starts: list[float] = []

    def respond(
        request: dns.message.Message,
        nameserver: str,
        tcp: bool,
    ) -> dns.message.Message:
        del nameserver, tcp
        query_starts.append(now[0])
        owner = request.question[0].name.to_text()
        if owner == "example.com.":
            response = cname(request, "alias.example.net.")
        elif request.question[0].rdtype == dns.rdatatype.A:
            response = answer(request, "A", "8.8.8.8")
        else:
            response = answer(request, "AAAA", "2001:4860:4860::8888")
        now[0] = 110.01 if len(query_starts) == 4 else now[0] + 2.5
        return response

    transport = FixtureTransport(("192.0.2.53",), respond)
    with pytest.raises(DNSAddressResolutionError):
        DNSAddressResolver(
            transport=transport,
            monotonic=lambda: now[0],
        ).resolve("example.com")
    assert query_starts == [100.0, 102.5, 105.0, 107.5]
    assert transport.deadlines == [103.0, 105.5, 108.0, 110.0]
    assert len(transport.requests) == 4


def test_nameserver_retry_does_not_start_after_overall_deadline() -> None:
    now = [100.0]

    def respond(
        request: dns.message.Message,
        nameserver: str,
        tcp: bool,
    ) -> dns.message.Message:
        del request, tcp
        assert nameserver == "192.0.2.53"
        now[0] = 110.01
        raise DNSAddressTransportError()

    transport = FixtureTransport(("192.0.2.53", "192.0.2.54"), respond)
    with pytest.raises(DNSAddressResolutionError):
        DNSAddressResolver(
            transport=transport,
            monotonic=lambda: now[0],
        ).resolve("example.com")
    assert transport.deadlines == [103.0]
    assert [nameserver for _, nameserver, _ in transport.requests] == ["192.0.2.53"]
