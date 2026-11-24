from __future__ import annotations

from collections.abc import Callable
import socket
import ssl
import time
from typing import cast

import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import pytest

from threat_sentinel_api.modules.networking.dns_address import (
    DNSAddressResolutionError,
    DNSAddressResolver,
)
from threat_sentinel_api.modules.networking.ip_policy import (
    ClassificationDecision,
    classify_ip_address,
    load_ip_policy,
)
from threat_sentinel_api.modules.networking.pinned_http import (
    PinnedHttpError,
    PinnedHttpResponse,
    PinnedHttpTransport,
    ScanBudget,
    TransportFailure,
)
from threat_sentinel_api.modules.networking.types import (
    AddressFamily,
    CanonicalAddress,
    ValidatedResolution,
)
from threat_sentinel_api.modules.targets.hostname import canonicalize_hostname


_CANONICAL_HOSTNAME = "example.com"
_INITIAL_ADDRESS = "8.8.8.8"
_REBOUND_ADDRESS = "1.1.1.1"
_NAMESERVER = "192.0.2.53"
_HTTP_RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"


class _FakeClock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class _FixtureDnsTransport:
    def __init__(
        self,
        ipv4_answers: tuple[str, ...] = (_INITIAL_ADDRESS,),
        rebound_address: str | None = None,
        on_query: Callable[[], None] | None = None,
    ) -> None:
        self._ipv4_answers = ipv4_answers
        self._rebound_address = rebound_address
        self._on_query = on_query
        self._a_query_count = 0
        self.queries: list[tuple[str, dns.rdatatype.RdataType, bool]] = []

    def nameservers(self) -> tuple[str, ...]:
        return (_NAMESERVER,)

    def query(
        self,
        request: dns.message.Message,
        *,
        nameserver: str,
        tcp: bool,
        deadline: float,
    ) -> dns.message.Message:
        del deadline
        question = request.question[0]
        self.queries.append((nameserver, question.rdtype, tcp))
        if self._on_query is not None:
            self._on_query()
        response = dns.message.make_response(request)
        if question.rdtype == dns.rdatatype.A:
            self._a_query_count += 1
            if self._a_query_count == 1:
                answers = self._ipv4_answers
            elif self._rebound_address is not None:
                answers = (self._rebound_address,)
            else:
                answers = self._ipv4_answers
            if answers:
                response.answer.append(
                    dns.rrset.from_text(
                        question.name,
                        60,
                        dns.rdataclass.IN,
                        dns.rdatatype.A,
                        *answers,
                    )
                )
        return response


class _FakeSocket:
    def __init__(
        self,
        response: bytes,
        certificate_hostname: str,
        clock: _FakeClock | None = None,
        connect_delay: float = 0.0,
    ) -> None:
        self.connected_to: tuple[object, ...] | None = None
        self.request = bytearray()
        self._response = response
        self.certificate_hostname = certificate_hostname
        self._clock = clock
        self._connect_delay = connect_delay
        self.server_name_indication: str | None = None
        self.verification_hostname: str | None = None
        self.verification_enabled: bool | None = None
        self.closed = False

    def connect(self, address: tuple[object, ...]) -> None:
        self.connected_to = address
        if self._clock is not None:
            self._clock.advance(self._connect_delay)

    def settimeout(self, _timeout: float) -> None:
        pass

    def sendall(self, value: bytes) -> None:
        self.request.extend(value)

    def recv(self, size: int) -> bytes:
        data = self._response[:size]
        self._response = self._response[size:]
        return data

    def selected_alpn_protocol(self) -> str:
        return "http/1.1"

    def close(self) -> None:
        self.closed = True


class _BoundaryPinnedHttpTransport(PinnedHttpTransport):
    def __init__(
        self,
        *,
        response: bytes = _HTTP_RESPONSE,
        certificate_hostname: str = _CANONICAL_HOSTNAME,
        clock: _FakeClock | None = None,
        connect_delay: float = 0.0,
    ) -> None:
        self._response = response
        self._certificate_hostname = certificate_hostname
        self._clock = clock
        self._connect_delay = connect_delay
        self.sockets: list[_FakeSocket] = []
        self.budgets: list[ScanBudget] = []

    def request(
        self,
        resolution: ValidatedResolution,
        *,
        scheme: str,
        method: str,
        budget: ScanBudget,
        address_family: AddressFamily | str | None = None,
    ) -> PinnedHttpResponse:
        self.budgets.append(budget)
        return super().request(
            resolution,
            scheme=scheme,
            method=method,
            budget=budget,
            address_family=address_family,
        )

    def _new_socket(self, _address: CanonicalAddress) -> socket.socket:
        fake_socket = _FakeSocket(
            self._response,
            self._certificate_hostname,
            self._clock,
            self._connect_delay,
        )
        self.sockets.append(fake_socket)
        return cast(socket.socket, fake_socket)

    @staticmethod
    def _wrap_tls(
        connection: socket.socket,
        context: ssl.SSLContext,
        hostname: str,
    ) -> ssl.SSLSocket:
        fake_socket = cast(_FakeSocket, connection)
        fake_socket.server_name_indication = hostname
        fake_socket.verification_hostname = hostname
        fake_socket.verification_enabled = (
            context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
        )
        if (
            not fake_socket.verification_enabled
            or fake_socket.certificate_hostname != hostname
        ):
            raise ssl.SSLCertVerificationError("fixture certificate hostname mismatch")
        return cast(ssl.SSLSocket, connection)


def _resolve(
    dns_transport: _FixtureDnsTransport,
    hostname: str = _CANONICAL_HOSTNAME,
) -> ValidatedResolution:
    result = DNSAddressResolver(transport=dns_transport).resolve(hostname)
    assert type(result) is ValidatedResolution
    return result


def _forbid_system_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: pytest.fail("unexpected system DNS lookup"),
    )
    monkeypatch.setattr(
        socket,
        "gethostbyname",
        lambda *_args, **_kwargs: pytest.fail("unexpected system DNS lookup"),
    )


def test_http_uses_resolved_literal_and_canonical_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _forbid_system_dns(monkeypatch)
    hostname = canonicalize_hostname("ExAmPle.COM.")
    dns_transport = _FixtureDnsTransport()
    resolution = _resolve(dns_transport, hostname)
    query_count = len(dns_transport.queries)
    budget = ScanBudget(time.monotonic() + 120.0)
    http_transport = _BoundaryPinnedHttpTransport()

    response = http_transport.request(
        resolution,
        scheme="http",
        method="GET",
        budget=budget,
    )

    policy = load_ip_policy()
    classification = classify_ip_address(response.destination_ip)
    assert response.hostname == _CANONICAL_HOSTNAME
    assert response.destination_ip == _INITIAL_ADDRESS
    assert http_transport.sockets[0].connected_to == (_INITIAL_ADDRESS, 80)
    assert b"Host: example.com\r\n" in http_transport.sockets[0].request
    assert response.status_code == 200
    assert response.body == b"ok"
    assert len(dns_transport.queries) == query_count
    assert resolution.policy_version == policy.policy_version
    assert classification.decision is ClassificationDecision.ALLOW
    assert classification.policy_version == resolution.policy_version


def test_https_identity_uses_canonical_hostname_and_pinned_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _forbid_system_dns(monkeypatch)
    hostname = canonicalize_hostname("EXAMPLE.com.")
    dns_transport = _FixtureDnsTransport()
    resolution = _resolve(dns_transport, hostname)
    query_count = len(dns_transport.queries)
    http_transport = _BoundaryPinnedHttpTransport()

    response = http_transport.request(
        resolution,
        scheme="https",
        method="GET",
        budget=ScanBudget(time.monotonic() + 120.0),
    )

    assert response.destination_ip == _INITIAL_ADDRESS
    assert http_transport.sockets[0].connected_to == (_INITIAL_ADDRESS, 443)
    assert http_transport.sockets[0].server_name_indication == _CANONICAL_HOSTNAME
    assert http_transport.sockets[0].verification_hostname == _CANONICAL_HOSTNAME
    assert http_transport.sockets[0].verification_enabled is True
    assert b"Host: example.com\r\n" in http_transport.sockets[0].request
    assert len(dns_transport.queries) == query_count
    assert response.status_code == 200
    assert response.body == b"ok"


def test_mixed_allowed_and_prohibited_dns_answers_fail_before_http(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _forbid_system_dns(monkeypatch)
    dns_transport = _FixtureDnsTransport(
        ipv4_answers=(_INITIAL_ADDRESS, "10.0.0.1"),
    )
    http_transport = _BoundaryPinnedHttpTransport()
    hostname = canonicalize_hostname("Example.COM.")

    with pytest.raises(DNSAddressResolutionError):
        resolution = _resolve(dns_transport, hostname)
        http_transport.request(
            resolution,
            scheme="http",
            method="GET",
            budget=ScanBudget(time.monotonic() + 120.0),
        )

    assert http_transport.sockets == []


def test_dns_rebinding_does_not_change_pinned_transport_destination(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _forbid_system_dns(monkeypatch)
    dns_transport = _FixtureDnsTransport(rebound_address=_REBOUND_ADDRESS)
    hostname = canonicalize_hostname("Example.COM.")
    resolution = _resolve(dns_transport, hostname)
    query_count = len(dns_transport.queries)
    http_transport = _BoundaryPinnedHttpTransport()

    response = http_transport.request(
        resolution,
        scheme="http",
        method="GET",
        budget=ScanBudget(time.monotonic() + 120.0),
    )

    assert response.destination_ip == _INITIAL_ADDRESS
    assert http_transport.sockets[0].connected_to == (_INITIAL_ADDRESS, 80)
    assert len(dns_transport.queries) == query_count

    followup = DNSAddressResolver(transport=dns_transport).resolve(hostname)
    assert followup.ipv4_addresses[0].address == _REBOUND_ADDRESS


def test_budget_created_before_resolution_is_reused_across_transport_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _forbid_system_dns(monkeypatch)
    budget = ScanBudget(time.monotonic() + 120.0)
    elapsed_before_resolution = budget.usage().elapsed_seconds
    dns_transport = _FixtureDnsTransport()
    resolution = DNSAddressResolver(transport=dns_transport).resolve(
        canonicalize_hostname("Example.COM."),
        overall_deadline=budget.deadline,
    )
    assert type(resolution) is ValidatedResolution
    elapsed_after_resolution = budget.usage().elapsed_seconds
    http_transport = _BoundaryPinnedHttpTransport()

    first = http_transport.request(
        resolution,
        scheme="http",
        method="GET",
        budget=budget,
    )
    second = http_transport.request(
        resolution,
        scheme="http",
        method="GET",
        budget=budget,
    )

    assert first.budget_usage.requests == 1
    assert second.budget_usage.requests == 2
    assert budget.usage().requests == 2
    assert elapsed_after_resolution >= elapsed_before_resolution
    assert budget.usage().elapsed_seconds >= elapsed_after_resolution
    assert len(http_transport.sockets) == 2
    assert all(sock.closed for sock in http_transport.sockets)


def test_dns_consumes_original_budget_before_http(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _forbid_system_dns(monkeypatch)
    clock = _FakeClock()
    monkeypatch.setattr(time, "monotonic", clock)
    budget = ScanBudget(clock() + 3.0)
    original_deadline = budget.deadline
    dns_transport = _FixtureDnsTransport(on_query=lambda: clock.advance(0.4))

    resolution = DNSAddressResolver(
        transport=dns_transport,
        monotonic=clock,
    ).resolve(
        _CANONICAL_HOSTNAME,
        overall_deadline=budget.deadline,
    )
    assert type(resolution) is ValidatedResolution
    assert len(dns_transport.queries) == 2
    assert clock() < original_deadline

    http_transport = _BoundaryPinnedHttpTransport(
        clock=clock,
        connect_delay=2.3,
    )
    with pytest.raises(PinnedHttpError) as error:
        http_transport.request(
            resolution,
            scheme="http",
            method="GET",
            budget=budget,
        )

    assert error.value.failure is TransportFailure.REQUEST_DEADLINE_EXHAUSTED
    assert clock() >= original_deadline
    assert budget.deadline == original_deadline
    assert http_transport.budgets == [budget]
    assert budget.usage().requests == 1
    assert len(http_transport.sockets) == 1
    assert http_transport.sockets[0].closed


def test_dns_exhausting_original_budget_prevents_http_invocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _forbid_system_dns(monkeypatch)
    clock = _FakeClock()
    monkeypatch.setattr(time, "monotonic", clock)
    budget = ScanBudget(clock() + 0.5)
    dns_transport = _FixtureDnsTransport(on_query=lambda: clock.advance(0.6))
    http_transport = _BoundaryPinnedHttpTransport(clock=clock)

    with pytest.raises(DNSAddressResolutionError):
        resolution = DNSAddressResolver(
            transport=dns_transport,
            monotonic=clock,
        ).resolve(
            _CANONICAL_HOSTNAME,
            overall_deadline=budget.deadline,
        )
        http_transport.request(
            resolution,
            scheme="http",
            method="GET",
            budget=budget,
        )

    assert clock() >= budget.deadline
    assert len(dns_transport.queries) == 1
    assert http_transport.budgets == []
    assert http_transport.sockets == []
    assert budget.usage().requests == 0
