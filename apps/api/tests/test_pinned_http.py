from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
import socket
import ssl
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from cryptography.x509.oid import NameOID
import pytest

from threat_sentinel_api.modules.networking import pinned_http
from threat_sentinel_api.modules.networking.pinned_http import (
    MAX_ENCODED_BODY_BYTES,
    MAX_RESPONSE_HEADER_BYTES,
    MAX_RESPONSE_HEADERS,
    MAX_SCAN_REQUESTS,
    MAX_SCAN_TRANSFERRED_BYTES,
    MAX_SCAN_IDENTITY_BYTES,
    HttpHeader,
    InvalidHttpResponse,
    PinnedHttpError,
    PinnedHttpTransport,
    ScanBudget,
    TransportFailure,
)
from threat_sentinel_api.modules.networking.types import (
    AddressFamily,
    FamilyResolution,
    ValidatedResolution,
)


def _resolution(
    ipv4: tuple[str, ...] = ("8.8.8.8",),
    ipv6: tuple[str, ...] = ("2001:4860:4860::8888",),
) -> ValidatedResolution:
    terminal = "example.com"
    return ValidatedResolution(
        hostname="Example.COM.",
        ipv4_addresses=ipv4,
        ipv6_addresses=ipv6,
        terminal_owner=terminal,
        resolved_at=datetime.now(UTC),
        total_deadline=datetime.now(UTC) + timedelta(seconds=10),
        family_results=(
            FamilyResolution(
                AddressFamily.IPV4,
                terminal,
                status="addresses" if ipv4 else "nodata",
                addresses=ipv4,
            ),
            FamilyResolution(
                AddressFamily.IPV6,
                terminal,
                status="addresses" if ipv6 else "nodata",
                addresses=ipv6,
            ),
        ),
    )


def _budget() -> ScanBudget:
    return ScanBudget(time.monotonic() + 120.0)


class _SocketAdapter:
    def __init__(self, raw: object) -> None:
        self.raw = raw
        self.connected_to: tuple[object, ...] | None = None

    def connect(self, address: tuple[object, ...]) -> None:
        self.connected_to = address

    def settimeout(self, timeout: float) -> None:
        self.raw.settimeout(timeout)  # type: ignore[attr-defined]

    def sendall(self, value: bytes) -> None:
        self.raw.sendall(value)  # type: ignore[attr-defined]

    def recv(self, size: int) -> bytes:
        return self.raw.recv(size)  # type: ignore[attr-defined]

    def close(self) -> None:
        self.raw.close()  # type: ignore[attr-defined]


class _SocketPairTransport(PinnedHttpTransport):
    def __init__(
        self,
        client: socket.socket,
        *,
        certificate_pem: bytes | None = None,
    ) -> None:
        self._client = client
        self._certificate_pem = certificate_pem
        self._adapter: _SocketAdapter | None = None
        self.server_name: str | None = None

    def _new_socket(self, _address: object) -> socket.socket:
        self._adapter = _SocketAdapter(self._client)
        return self._adapter  # type: ignore[return-value]

    def _tls_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context()
        if self._certificate_pem is not None:
            context.load_verify_locations(cadata=self._certificate_pem.decode("ascii"))
        return context

    def _wrap_tls(
        self,
        connection: socket.socket,
        context: ssl.SSLContext,
        hostname: str,
    ) -> ssl.SSLSocket:
        self.server_name = hostname
        adapter = connection  # test-only adapter injected by _new_socket
        return context.wrap_socket(  # type: ignore[arg-type]
            adapter.raw,  # type: ignore[attr-defined]
            server_hostname=hostname,
            do_handshake_on_connect=True,
        )


def _start_response_peer(
    peer: socket.socket,
    response: bytes,
    *,
    server_context: ssl.SSLContext | None = None,
    server_names: list[str | None] | None = None,
) -> tuple[threading.Thread, list[bytes], list[Exception]]:
    requests: list[bytes] = []
    errors: list[Exception] = []

    def serve() -> None:
        stream: socket.socket | ssl.SSLSocket = peer
        try:
            if server_context is not None:
                if server_names is not None:
                    server_context.set_servername_callback(
                        lambda _socket, name, _context: server_names.append(name)
                    )
                stream = server_context.wrap_socket(peer, server_side=True)
            request = bytearray()
            while not request.endswith(b"\r\n\r\n"):
                part = stream.recv(4096)
                if not part:
                    raise AssertionError("request closed before headers completed")
                request.extend(part)
                if len(request) > 4096:
                    raise AssertionError("unexpected request bytes")
            requests.append(bytes(request))
            stream.sendall(response)
        except Exception as error:
            errors.append(error)
        finally:
            stream.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return thread, requests, errors


def _tls_fixture(
    tmp_path: Path,
    *,
    hostname: str = "example.com",
    alpn: tuple[str, ...] | None = ("http/1.1",),
) -> tuple[ssl.SSLContext, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    certificate_pem = certificate.public_bytes(Encoding.PEM)
    key_pem = key.private_bytes(
        Encoding.PEM,
        PrivateFormat.TraditionalOpenSSL,
        NoEncryption(),
    )
    certificate_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    certificate_path.write_bytes(certificate_pem)
    key_path.write_bytes(key_pem)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate_path, key_path)
    if alpn is not None:
        context.set_alpn_protocols(list(alpn))
    return context, certificate_pem


def _exchange(
    response: bytes,
    *,
    scheme: str = "http",
    method: str = "GET",
    resolution: ValidatedResolution | None = None,
    family: AddressFamily | str | None = None,
    server_context: ssl.SSLContext | None = None,
    certificate_pem: bytes | None = None,
    server_names: list[str | None] | None = None,
    budget: ScanBudget | None = None,
) -> tuple[object, bytes, tuple[object, ...] | None, list[Exception]]:
    client, peer = socket.socketpair()
    thread, requests, errors = _start_response_peer(
        peer,
        response,
        server_context=server_context,
        server_names=server_names,
    )
    transport = _SocketPairTransport(client, certificate_pem=certificate_pem)
    try:
        result = transport.request(
            resolution or _resolution(),
            scheme=scheme,
            method=method,
            budget=budget or _budget(),
            address_family=family,
        )
    finally:
        thread.join(timeout=2)
    assert not thread.is_alive()
    assert not errors
    assert len(requests) == 1
    assert transport._adapter is not None
    assert client.fileno() == -1
    return result, requests[0], transport._adapter.connected_to, errors


def test_pins_ipv4_and_ipv6_candidates_and_never_resolves_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: pytest.fail("unexpected DNS lookup"),
    )
    monkeypatch.setattr(
        socket,
        "gethostbyname",
        lambda *_args, **_kwargs: pytest.fail("unexpected DNS lookup"),
    )
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

    v4, _, connected_v4, _ = _exchange(response, family=AddressFamily.IPV4)
    v6, _, connected_v6, _ = _exchange(response, family=AddressFamily.IPV6)

    assert connected_v4 == ("8.8.8.8", 80)
    assert connected_v6 == ("2001:4860:4860::8888", 80, 0, 0)
    assert v4.destination_ip == "8.8.8.8"
    assert v6.destination_ip == "2001:4860:4860::8888"


def test_rejects_missing_candidate_and_invalid_resolution_policy() -> None:
    client, peer = socket.socketpair()
    peer.close()
    transport = _SocketPairTransport(client)
    with pytest.raises(PinnedHttpError) as no_v6:
        transport.request(
            _resolution(ipv4=("8.8.8.8",), ipv6=()),
            scheme="http",
            method="GET",
            budget=_budget(),
            address_family=AddressFamily.IPV6,
        )
    assert no_v6.value.failure is TransportFailure.TARGET_ADDRESS_UNAVAILABLE
    client.close()

    invalid = _resolution()
    object.__setattr__(invalid, "policy_version", "other")
    client, peer = socket.socketpair()
    peer.close()
    with pytest.raises(PinnedHttpError) as invalid_resolution:
        _SocketPairTransport(client).get(
            invalid,
            scheme="http",
            budget=_budget(),
        )
    assert invalid_resolution.value.failure is TransportFailure.TARGET_ADDRESS_UNAVAILABLE
    client.close()


def test_proxy_environment_is_ignored_and_request_is_fixed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
    ):
        monkeypatch.setenv(name, "http://127.0.0.1:8888")
    result, request, connected, _ = _exchange(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    )

    assert request == (
        b"GET / HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Accept-Encoding: identity\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    assert connected == ("8.8.8.8", 80)
    assert result.body == b""


@pytest.mark.parametrize(
    ("method", "request_line"),
    [("GET", b"GET / HTTP/1.1\r\n"), ("HEAD", b"HEAD / HTTP/1.1\r\n")],
)
def test_only_get_and_head_are_sent_with_no_body(
    method: str,
    request_line: bytes,
) -> None:
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    result, request, _, _ = _exchange(response, method=method)
    assert request.startswith(request_line)
    assert request.endswith(b"\r\n\r\n")
    assert result.method == method


def test_http_uses_only_approved_port() -> None:
    result, _, connected, _ = _exchange(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        scheme="http",
    )
    assert result.port == 80
    assert connected == ("8.8.8.8", 80)


@pytest.mark.parametrize(
    ("scheme", "method"),
    [
        ("ftp", "GET"),
        ("https", "POST"),
        ("https", "get"),
    ],
)
def test_arbitrary_scheme_and_method_are_rejected(scheme: str, method: str) -> None:
    client, peer = socket.socketpair()
    peer.close()
    with pytest.raises(ValueError):
        PinnedHttpTransport().request(
            _resolution(),
            scheme=scheme,
            method=method,
            budget=_budget(),
        )
    client.close()


def test_rejects_raw_destination_and_caller_supplied_request_body() -> None:
    transport = PinnedHttpTransport()
    with pytest.raises(TypeError):
        transport.request(  # type: ignore[call-arg]
            _resolution(),
            scheme="http",
            method="GET",
            budget=_budget(),
            destination_ip="8.8.4.4",
        )
    with pytest.raises(TypeError):
        transport.request(  # type: ignore[call-arg]
            _resolution(),
            scheme="http",
            method="GET",
            budget=_budget(),
            body=b"unexpected",
        )


def test_redirect_is_observed_and_never_followed() -> None:
    result, request, _, _ = _exchange(
        b"HTTP/1.1 302 Found\r\n"
        b"Location: https://other.example/path\r\n"
        b"Content-Length: 0\r\n\r\n"
    )
    assert result.is_redirect
    assert result.redirect_location == "https://other.example/path"
    assert result.status_code == 302
    assert request.count(b"GET ") == 1


def test_duplicate_non_framing_headers_remain_distinct_metadata() -> None:
    response, _, _, _ = _exchange(
        b"HTTP/1.1 200 OK\r\n"
        b"X-Repeat: first\r\n"
        b"X-Repeat: second\r\n"
        b"Content-Length: 0\r\n\r\n"
    )
    assert response.headers == (
        HttpHeader("x-repeat", "first"),
        HttpHeader("x-repeat", "second"),
        HttpHeader("content-length", "0"),
    )


def test_tls_uses_system_roots_hostname_verification_sni_and_http11(
    tmp_path: Path,
) -> None:
    server_context, certificate = _tls_fixture(tmp_path)
    client, peer = socket.socketpair()
    server_names: list[str | None] = []
    thread, requests, errors = _start_response_peer(
        peer,
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        server_context=server_context,
        server_names=server_names,
    )
    transport = _SocketPairTransport(client, certificate_pem=certificate)
    response = transport.get(_resolution(), scheme="https", budget=_budget())
    thread.join(timeout=2)

    assert not thread.is_alive()
    assert not errors
    assert response.status_code == 200
    assert transport.server_name == "example.com"
    assert server_names == ["example.com"]
    assert requests[0].startswith(b"GET / HTTP/1.1\r\nHost: example.com\r\n")
    assert transport._adapter is not None
    assert transport._adapter.connected_to == ("8.8.8.8", 443)
    assert client.fileno() == -1


def test_tls_rejects_wrong_certificate_hostname(tmp_path: Path) -> None:
    server_context, certificate = _tls_fixture(tmp_path, hostname="other.example")
    client, peer = socket.socketpair()
    thread, _, _ = _start_response_peer(
        peer,
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        server_context=server_context,
    )
    transport = _SocketPairTransport(client, certificate_pem=certificate)
    with pytest.raises(PinnedHttpError) as error:
        transport.get(_resolution(), scheme="https", budget=_budget())
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert error.value.failure is TransportFailure.TLS_VERIFICATION_FAILED


@pytest.mark.parametrize("alpn", [None, ("h2",)])
def test_tls_rejects_missing_or_non_http11_alpn(
    tmp_path: Path,
    alpn: tuple[str, ...] | None,
) -> None:
    server_context, certificate = _tls_fixture(tmp_path, alpn=alpn)
    client, peer = socket.socketpair()
    thread, _, _ = _start_response_peer(
        peer,
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        server_context=server_context,
    )
    transport = _SocketPairTransport(client, certificate_pem=certificate)
    with pytest.raises(PinnedHttpError) as error:
        transport.get(_resolution(), scheme="https", budget=_budget())
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert error.value.failure is TransportFailure.TLS_VERIFICATION_FAILED


def test_http_does_not_create_tls_session() -> None:
    result, _, _, _ = _exchange(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        scheme="http",
    )
    assert result.scheme == "http"
    assert result.timings.tls_seconds == 0


@pytest.mark.parametrize(
    "headers",
    [
        b"Content-Length: 1\r\nContent-Length: 1\r\n",
        b"Content-Length: 1\r\nContent-Length: 2\r\n",
        b"Content-Length: 1\r\nTransfer-Encoding: chunked\r\n",
        b"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
        b"Transfer-Encoding: gzip, chunked\r\n",
        b"Transfer-Encoding: gzip\r\n",
        b"Transfer-Encoding: Chunked\r\n",
        b"Content-Length: +1\r\n",
        b"Content-Length: 999999999999999999999999999999999999999999\r\n",
        b"Content-Encoding: gzip\r\n",
        b"Content-Encoding: identity\r\nContent-Encoding: identity\r\n",
        b"Content-Encoding: identity, gzip\r\n",
    ],
)
def test_rejects_ambiguous_or_unsupported_response_headers(headers: bytes) -> None:
    response = b"HTTP/1.1 200 OK\r\n" + headers + b"\r\n"
    with pytest.raises(InvalidHttpResponse):
        _exchange(response)


@pytest.mark.parametrize(
    "response",
    [
        b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 20 OK\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200OK\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n X-Folded: value\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nX-Control: a\x01b\r\nContent-Length: 0\r\n\r\n",
    ],
)
def test_rejects_invalid_status_and_header_syntax(response: bytes) -> None:
    with pytest.raises(InvalidHttpResponse):
        _exchange(response)


def test_identity_content_encoding_is_returned_without_decompression() -> None:
    response, _, _, _ = _exchange(
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Encoding: identity\r\n"
        b"Content-Length: 3\r\n\r\n"
        b"abc"
    )
    assert response.body == b"abc"
    assert response.headers[0] == HttpHeader("content-encoding", "identity")


def test_parses_chunked_response_and_keeps_trailers_separate() -> None:
    payload = (
        b"HTTP/1.1 200 OK\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"4\r\nWiki\r\n"
        b"5\r\npedia\r\n"
        b"0\r\n"
        b"X-Checksum: yes\r\n"
        b"\r\n"
    )
    response, _, _, _ = _exchange(
        payload
    )
    assert response.body == b"Wikipedia"
    assert response.trailers == (HttpHeader("x-checksum", "yes"),)
    assert response.encoded_body_bytes == 9
    assert response.decompressed_body_bytes == 9
    assert response.response_transferred_bytes == len(payload)


@pytest.mark.parametrize(
    "chunked_body",
    [
        b"z\r\n",
        b"1\r\naXX",
        b"2\r\na\r\n0\r\n\r\n",
        b"1;extension=x\r\na\r\n0\r\n\r\n",
        b"1\r\na\r\n0\r\nContent-Length: 1\r\n\r\n",
        b"1\r\na\r\n0\r\nX-Note: safe\r\nX-Note: duplicate\r\n\r\n",
        b"1\r\na\r\n0\r\nSet-Cookie: session=x\r\n\r\n",
        b"fffffffffffffffff\r\n",
    ],
)
def test_rejects_malformed_chunking_or_trailer_override(chunked_body: bytes) -> None:
    response = (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked_body
    )
    with pytest.raises(InvalidHttpResponse):
        _exchange(response)


def test_response_body_is_not_exposed_after_parse_failure() -> None:
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"
        b"HTTP/1.1 200 OK\r\n"
    )
    with pytest.raises(InvalidHttpResponse) as error:
        _exchange(response)
    assert not hasattr(error.value, "body")


def test_rejects_close_delimited_and_incomplete_responses() -> None:
    for response in (
        b"HTTP/1.1 200 OK\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nab",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\na",
    ):
        with pytest.raises(InvalidHttpResponse):
            _exchange(response)


def test_no_body_semantics_for_head_informational_204_205_and_304() -> None:
    head, _, _, _ = _exchange(
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n",
        method="HEAD",
    )
    informational, _, _, _ = _exchange(
        b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\n"
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    )
    no_content, _, _, _ = _exchange(b"HTTP/1.1 204 No Content\r\n\r\n")
    reset, _, _, _ = _exchange(b"HTTP/1.1 205 Reset Content\r\nContent-Length: 0\r\n\r\n")
    not_modified, _, _, _ = _exchange(
        b"HTTP/1.1 304 Not Modified\r\nContent-Length: 3\r\n\r\n"
    )

    assert head.body == b""
    assert informational.status_code == 200
    assert no_content.body == b""
    assert reset.body == b""
    assert not_modified.body == b""


def _header_response(lines: list[bytes]) -> bytes:
    return b"HTTP/1.1 200 OK\r\n" + b"".join(lines) + b"\r\n"


def test_response_header_count_boundary() -> None:
    valid_lines = [b"Content-Length: 0\r\n"] + [
        f"X-{index}: a\r\n".encode() for index in range(MAX_RESPONSE_HEADERS - 1)
    ]
    response, _, _, _ = _exchange(_header_response(valid_lines))
    assert response.body == b""

    invalid_lines = valid_lines + [b"X-Extra: a\r\n"]
    with pytest.raises(PinnedHttpError) as error:
        _exchange(_header_response(invalid_lines))
    assert error.value.failure is TransportFailure.RESPONSE_LIMIT_EXCEEDED


def test_response_header_line_and_aggregate_boundaries() -> None:
    exact_line_value = b"a" * (8192 - len(b"X: \r\n"))
    exact, _, _, _ = _exchange(
        _header_response([b"Content-Length: 0\r\n", b"X: " + exact_line_value + b"\r\n"])
    )
    assert exact.body == b""
    over_line_value = b"a" * (8193 - len(b"X: \r\n"))
    with pytest.raises(PinnedHttpError):
        _exchange(
            _header_response([b"Content-Length: 0\r\n", b"X: " + over_line_value + b"\r\n"])
        )

    prefix = b"HTTP/1.1 200 OK\r\n"
    content_length = b"Content-Length: 0\r\n"
    remaining = MAX_RESPONSE_HEADER_BYTES - len(prefix) - len(content_length) - 2
    filler_lines = []
    for index in range(4):
        line_length = remaining // (4 - index)
        remaining -= line_length
        filler_lines.append(
            f"X{index}: ".encode()
            + b"a" * (line_length - len(f"X{index}: \r\n".encode()))
            + b"\r\n"
        )
    exact_aggregate = prefix + content_length + b"".join(filler_lines) + b"\r\n"
    assert len(exact_aggregate) == MAX_RESPONSE_HEADER_BYTES
    exact, _, _, _ = _exchange(exact_aggregate)
    assert exact.body == b""
    with pytest.raises(PinnedHttpError):
        _exchange(exact_aggregate[:-2] + b"X\r\n\r\n")


def test_encoded_response_body_limit_and_scan_budget_counters() -> None:
    exact_body = b"x" * MAX_ENCODED_BODY_BYTES
    exact, _, _, _ = _exchange(
        b"HTTP/1.1 200 OK\r\nContent-Length: "
        + str(len(exact_body)).encode()
        + b"\r\n\r\n"
        + exact_body
    )
    assert len(exact.body) == MAX_ENCODED_BODY_BYTES
    assert exact.encoded_body_bytes == exact.decompressed_body_bytes
    assert exact.budget_usage.identity_bytes == len(exact_body)
    assert exact.budget_usage.decompressed_bytes == len(exact_body)

    with pytest.raises(PinnedHttpError) as too_large:
        _exchange(
            b"HTTP/1.1 200 OK\r\nContent-Length: "
            + str(MAX_ENCODED_BODY_BYTES + 1).encode()
            + b"\r\n\r\n"
        )
    assert too_large.value.failure is TransportFailure.RESPONSE_LIMIT_EXCEEDED

    budget = _budget()
    budget.charge_transferred(MAX_SCAN_TRANSFERRED_BYTES)
    with pytest.raises(PinnedHttpError):
        _exchange(
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            budget=budget,
        )


def test_cumulative_scan_budget_rejects_requests_and_identity_bytes() -> None:
    budget = _budget()
    budget.charge_identity(MAX_SCAN_IDENTITY_BYTES)
    with pytest.raises(PinnedHttpError):
        budget.charge_identity(1)
    for _ in range(MAX_SCAN_REQUESTS):
        budget.begin_request()
    with pytest.raises(PinnedHttpError) as request_limit:
        budget.begin_request()
    assert request_limit.value.failure is TransportFailure.RESPONSE_LIMIT_EXCEEDED
    usage = budget.usage()
    assert usage.requests == MAX_SCAN_REQUESTS
    assert usage.identity_bytes == MAX_SCAN_IDENTITY_BYTES
    assert usage.decompressed_bytes == MAX_SCAN_IDENTITY_BYTES


def test_per_response_transferred_bytes_are_limited() -> None:
    chunks = b"1\r\nx\r\n" * 350_000
    response = (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        + chunks
        + b"0\r\n\r\n"
    )
    with pytest.raises(PinnedHttpError) as error:
        _exchange(response)
    assert error.value.failure is TransportFailure.RESPONSE_LIMIT_EXCEEDED


def test_scan_deadline_cannot_exceed_120_seconds() -> None:
    with pytest.raises(ValueError, match="invalid_scan_deadline"):
        ScanBudget(time.monotonic() + 121)


class _FakeClock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class _FakeSocket:
    def __init__(
        self,
        clock: _FakeClock,
        response_parts: list[tuple[bytes, float]] | None = None,
        *,
        connect_delay: float = 0.0,
    ) -> None:
        self.clock = clock
        self.response_parts = list(response_parts or [])
        self.connect_delay = connect_delay
        self.request = bytearray()
        self.timeout_values: list[float] = []
        self.closed = False

    def settimeout(self, timeout: float) -> None:
        self.timeout_values.append(timeout)

    def sendall(self, value: bytes) -> None:
        self.request.extend(value)

    def recv(self, maximum: int) -> bytes:
        if not self.response_parts:
            raise socket.timeout
        payload, delay = self.response_parts.pop(0)
        self.clock.advance(delay)
        if len(payload) > maximum:
            self.response_parts.insert(0, (payload[maximum:], 0.0))
            payload = payload[:maximum]
        return payload

    def close(self) -> None:
        self.closed = True


class _FakeTransport(PinnedHttpTransport):
    def __init__(
        self,
        fake_socket: _FakeSocket,
        *,
        tls_delay: float = 0.0,
        context_setup_delay: float = 0.0,
        selected_alpn: str = "http/1.1",
    ) -> None:
        self.fake_socket = fake_socket
        self.tls_delay = tls_delay
        self.context_setup_delay = context_setup_delay
        self._selected_alpn = selected_alpn
        self.handshake_started = False
        self.handshake_timeout: float | None = None

    def _new_socket(self, _address: object) -> socket.socket:
        return _SocketAdapter(self.fake_socket)  # type: ignore[return-value]

    def _tls_context(self) -> ssl.SSLContext:
        context = super()._tls_context()
        self.fake_socket.clock.advance(self.context_setup_delay)
        return context

    def _wrap_tls(
        self,
        _connection: socket.socket,
        _context: ssl.SSLContext,
        _hostname: str,
    ) -> ssl.SSLSocket:
        self.handshake_started = True
        self.handshake_timeout = self.fake_socket.timeout_values[-1]
        self.fake_socket.clock.advance(self.tls_delay)
        return _FakeTlsSocket(self.fake_socket, self._selected_alpn)  # type: ignore[return-value]


class _FakeTlsSocket(_FakeSocket):
    def __init__(self, raw: _FakeSocket, selected_alpn: str) -> None:
        self.raw = raw
        self.selected_alpn = selected_alpn

    @property
    def clock(self) -> _FakeClock:
        return self.raw.clock

    @property
    def closed(self) -> bool:
        return self.raw.closed

    def settimeout(self, timeout: float) -> None:
        self.raw.settimeout(timeout)

    def sendall(self, value: bytes) -> None:
        self.raw.sendall(value)

    def recv(self, maximum: int) -> bytes:
        return self.raw.recv(maximum)

    def close(self) -> None:
        self.raw.close()

    def selected_alpn_protocol(self) -> str:
        return self.selected_alpn


def _fake_transport(
    monkeypatch: pytest.MonkeyPatch,
    *,
    parts: list[tuple[bytes, float]] | None = None,
    connect_delay: float = 0.0,
    tls_delay: float = 0.0,
    context_setup_delay: float = 0.0,
    selected_alpn: str = "http/1.1",
    scan_deadline_delta: float = 120.0,
) -> tuple[_FakeTransport, _FakeClock, ScanBudget]:
    clock = _FakeClock()
    monkeypatch.setattr(pinned_http.time, "monotonic", clock)
    fake_socket = _FakeSocket(clock, parts, connect_delay=connect_delay)
    transport = _FakeTransport(
        fake_socket,
        tls_delay=tls_delay,
        context_setup_delay=context_setup_delay,
        selected_alpn=selected_alpn,
    )
    budget = ScanBudget(clock() + scan_deadline_delta)
    return transport, clock, budget


def test_tcp_connect_deadline_rejects_late_success(monkeypatch: pytest.MonkeyPatch) -> None:
    transport, clock, budget = _fake_transport(
        monkeypatch,
        parts=[(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 0.0)],
        connect_delay=3.1,
    )
    transport._connect = lambda *_args: clock.advance(3.1)  # type: ignore[method-assign]
    with pytest.raises(PinnedHttpError) as error:
        transport.get(_resolution(), scheme="http", budget=budget)
    assert error.value.failure is TransportFailure.CONNECTION_REFUSED_OR_TIMED_OUT


def test_tls_handshake_deadline_rejects_late_success(monkeypatch: pytest.MonkeyPatch) -> None:
    transport, _, budget = _fake_transport(
        monkeypatch,
        parts=[(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 0.0)],
        tls_delay=5.1,
    )
    with pytest.raises(PinnedHttpError) as error:
        transport.get(_resolution(), scheme="https", budget=budget)
    assert error.value.failure is TransportFailure.CONNECTION_REFUSED_OR_TIMED_OUT


def test_tls_context_setup_refreshes_timeout_to_remaining_phase_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport, _, budget = _fake_transport(
        monkeypatch,
        parts=[(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 0.0)],
        context_setup_delay=1.25,
    )

    transport.get(_resolution(), scheme="https", budget=budget)

    assert transport.fake_socket.timeout_values[1] == 5.0
    assert transport.handshake_timeout == pytest.approx(3.75)


@pytest.mark.parametrize(
    ("context_setup_delay", "scan_deadline_delta", "failure"),
    [
        (5.1, 120.0, TransportFailure.CONNECTION_REFUSED_OR_TIMED_OUT),
        (4.1, 4.0, TransportFailure.REQUEST_DEADLINE_EXHAUSTED),
    ],
)
def test_expired_tls_or_request_deadline_prevents_handshake(
    monkeypatch: pytest.MonkeyPatch,
    context_setup_delay: float,
    scan_deadline_delta: float,
    failure: TransportFailure,
) -> None:
    transport, _, budget = _fake_transport(
        monkeypatch,
        context_setup_delay=context_setup_delay,
        scan_deadline_delta=scan_deadline_delta,
    )

    with pytest.raises(PinnedHttpError) as error:
        transport.get(_resolution(), scheme="https", budget=budget)

    assert error.value.failure is failure
    assert not transport.handshake_started


def test_first_byte_and_read_inactivity_deadlines_reject_late_data(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, _, first_budget = _fake_transport(
        monkeypatch,
        parts=[(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 5.1)],
    )
    with pytest.raises(PinnedHttpError) as first_error:
        first.get(_resolution(), scheme="http", budget=first_budget)
    assert first_error.value.failure is TransportFailure.CONNECTION_REFUSED_OR_TIMED_OUT

    inactivity, _, inactivity_budget = _fake_transport(
        monkeypatch,
        parts=[
            (b"HTTP/1.1 200 OK\r\n", 0.0),
            (b"Content-Length: 0\r\n\r\n", 2.1),
        ],
    )
    with pytest.raises(PinnedHttpError) as inactivity_error:
        inactivity.get(_resolution(), scheme="http", budget=inactivity_budget)
    assert (
        inactivity_error.value.failure
        is TransportFailure.CONNECTION_REFUSED_OR_TIMED_OUT
    )


def test_total_request_deadline_overrides_phase_and_rejects_late_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport, _, budget = _fake_transport(
        monkeypatch,
        parts=[(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 0.6)],
        scan_deadline_delta=0.5,
    )
    with pytest.raises(PinnedHttpError) as error:
        transport.get(_resolution(), scheme="http", budget=budget)
    assert error.value.failure is TransportFailure.REQUEST_DEADLINE_EXHAUSTED

    body, _, body_budget = _fake_transport(
        monkeypatch,
        parts=[
            (b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n", 0.0),
            (b"body", 2.1),
        ],
    )
    with pytest.raises(PinnedHttpError) as body_error:
        body.get(_resolution(), scheme="http", budget=body_budget)
    assert (
        body_error.value.failure is TransportFailure.CONNECTION_REFUSED_OR_TIMED_OUT
    )


def test_non_http11_alpn_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    transport, _, budget = _fake_transport(
        monkeypatch,
        parts=[(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 0.0)],
        selected_alpn="h2",
    )
    with pytest.raises(PinnedHttpError) as error:
        transport.get(_resolution(), scheme="https", budget=budget)
    assert error.value.failure is TransportFailure.TLS_VERIFICATION_FAILED


def test_http_response_model_is_immutable() -> None:
    result, _, _, _ = _exchange(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    with pytest.raises((AttributeError, TypeError)):
        result.status_code = 201
