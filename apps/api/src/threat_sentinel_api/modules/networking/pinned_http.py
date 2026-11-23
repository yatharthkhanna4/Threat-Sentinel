"""One-shot HTTP/1.1 transport over an already validated, pinned IP address."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import ipaddress
import math
import socket
import ssl
import threading
import time
from typing import Final

from .ip_policy import ClassificationDecision, POLICY_VERSION, classify_ip_address
from .types import (
    AddressFamily,
    CanonicalAddress,
    FamilyResolution,
    ResolutionStatus,
    ValidatedResolution,
)
from threat_sentinel_api.modules.targets.hostname import CanonicalHostname


TCP_CONNECT_TIMEOUT_SECONDS: Final = 3.0
TLS_HANDSHAKE_TIMEOUT_SECONDS: Final = 5.0
FIRST_BYTE_TIMEOUT_SECONDS: Final = 5.0
READ_INACTIVITY_TIMEOUT_SECONDS: Final = 2.0
HTTP_REQUEST_TIMEOUT_SECONDS: Final = 10.0
SCAN_DEADLINE_SECONDS: Final = 120.0

MAX_RESPONSE_HEADERS: Final = 64
MAX_RESPONSE_HEADER_BYTES: Final = 32 * 1024
MAX_HEADER_LINE_BYTES: Final = 8 * 1024
MAX_ENCODED_BODY_BYTES: Final = 1024 * 1024
MAX_DECOMPRESSED_BODY_BYTES: Final = 2 * 1024 * 1024
MAX_RESPONSE_TRANSFERRED_BYTES: Final = 2 * 1024 * 1024
MAX_SCAN_TRANSFERRED_BYTES: Final = 5 * 1024 * 1024
MAX_SCAN_IDENTITY_BYTES: Final = 5 * 1024 * 1024
MAX_SCAN_REQUESTS: Final = 20

_HEADER_TOKEN: Final = frozenset(
    b"!#$%&'*+-.^_`|~"
    b"0123456789"
    b"abcdefghijklmnopqrstuvwxyz"
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
)
_TRAILER_FORBIDDEN: Final = frozenset(
    {
        "authorization",
        "cache-control",
        "connection",
        "content-security-policy",
        "content-security-policy-report-only",
        "content-encoding",
        "content-length",
        "cross-origin-embedder-policy",
        "cross-origin-opener-policy",
        "cross-origin-resource-policy",
        "host",
        "location",
        "permissions-policy",
        "proxy-authenticate",
        "proxy-authorization",
        "referrer-policy",
        "set-cookie",
        "strict-transport-security",
        "transfer-encoding",
        "vary",
        "www-authenticate",
        "x-content-type-options",
        "x-frame-options",
    }
)


class TransportFailure(StrEnum):
    TARGET_ADDRESS_UNAVAILABLE = "target_address_unavailable"
    CONNECTION_REFUSED_OR_TIMED_OUT = "connection_refused_or_timed_out"
    TLS_VERIFICATION_FAILED = "tls_verification_failed"
    RESPONSE_LIMIT_EXCEEDED = "response_limit_exceeded"
    REQUEST_DEADLINE_EXHAUSTED = "request_deadline_exhausted"


class PinnedHttpError(RuntimeError):
    """A generic, stable outbound transport failure."""

    def __init__(self, failure: TransportFailure) -> None:
        self.failure = failure
        message = {
            TransportFailure.TARGET_ADDRESS_UNAVAILABLE: "Target address is unavailable.",
            TransportFailure.CONNECTION_REFUSED_OR_TIMED_OUT: (
                "Outbound connection was refused or timed out."
            ),
            TransportFailure.TLS_VERIFICATION_FAILED: "TLS verification failed.",
            TransportFailure.RESPONSE_LIMIT_EXCEEDED: "Outbound response was rejected.",
            TransportFailure.REQUEST_DEADLINE_EXHAUSTED: "Outbound request deadline exhausted.",
        }[failure]
        super().__init__(message)


class InvalidHttpResponse(PinnedHttpError):
    """A malformed or ambiguous HTTP response rejected without exposing wire data."""

    def __init__(self) -> None:
        super().__init__(TransportFailure.RESPONSE_LIMIT_EXCEEDED)


class _DeadlineExpired(PinnedHttpError):
    def __init__(self) -> None:
        super().__init__(TransportFailure.REQUEST_DEADLINE_EXHAUSTED)


class _BudgetExceeded(PinnedHttpError):
    def __init__(self) -> None:
        super().__init__(TransportFailure.RESPONSE_LIMIT_EXCEEDED)


@dataclass(frozen=True, slots=True)
class ScanBudgetUsage:
    requests: int
    transferred_bytes: int
    identity_bytes: int
    decompressed_bytes: int
    elapsed_seconds: float
    remaining_seconds: float


class ScanBudget:
    """Thread-safe per-scan accounting, created with the caller's absolute deadline."""

    __slots__ = (
        "_deadline",
        "_started_at",
        "_requests",
        "_transferred_bytes",
        "_identity_bytes",
        "_lock",
    )

    def __init__(self, deadline: float) -> None:
        if isinstance(deadline, bool) or not isinstance(deadline, (float, int)):
            raise ValueError("invalid_scan_deadline")
        if not math.isfinite(deadline):
            raise ValueError("invalid_scan_deadline")
        now = time.monotonic()
        if deadline <= now or deadline > now + SCAN_DEADLINE_SECONDS:
            raise ValueError("invalid_scan_deadline")
        self._started_at = now
        self._deadline = float(deadline)
        self._requests = 0
        self._transferred_bytes = 0
        self._identity_bytes = 0
        self._lock = threading.Lock()

    @property
    def deadline(self) -> float:
        return self._deadline

    def check_deadline(self) -> None:
        if time.monotonic() >= self._deadline:
            raise _DeadlineExpired()

    def begin_request(self) -> None:
        self.check_deadline()
        with self._lock:
            if self._requests >= MAX_SCAN_REQUESTS:
                raise _BudgetExceeded()
            self._requests += 1

    def charge_transferred(self, byte_count: int) -> None:
        if byte_count < 0:
            raise ValueError("invalid_byte_count")
        if not byte_count:
            return
        with self._lock:
            if self._transferred_bytes + byte_count > MAX_SCAN_TRANSFERRED_BYTES:
                raise _BudgetExceeded()
            self._transferred_bytes += byte_count

    def charge_identity(self, byte_count: int) -> None:
        if byte_count < 0:
            raise ValueError("invalid_byte_count")
        if not byte_count:
            return
        with self._lock:
            if self._identity_bytes + byte_count > MAX_SCAN_IDENTITY_BYTES:
                raise _BudgetExceeded()
            self._identity_bytes += byte_count

    def usage(self) -> ScanBudgetUsage:
        now = time.monotonic()
        with self._lock:
            requests = self._requests
            transferred = self._transferred_bytes
            identity = self._identity_bytes
        return ScanBudgetUsage(
            requests=requests,
            transferred_bytes=transferred,
            identity_bytes=identity,
            decompressed_bytes=identity,
            elapsed_seconds=max(0.0, now - self._started_at),
            remaining_seconds=max(0.0, self._deadline - now),
        )


@dataclass(frozen=True, slots=True)
class HttpHeader:
    name: str
    value: str


@dataclass(frozen=True, slots=True)
class TransportTimings:
    connect_seconds: float
    tls_seconds: float
    first_byte_seconds: float
    response_read_seconds: float
    total_seconds: float


@dataclass(frozen=True, slots=True)
class PinnedHttpResponse:
    hostname: str
    destination_ip: str
    scheme: str
    port: int
    method: str
    status_code: int
    reason: str
    headers: tuple[HttpHeader, ...]
    trailers: tuple[HttpHeader, ...]
    is_redirect: bool
    redirect_location: str | None
    body: bytes
    response_transferred_bytes: int
    encoded_body_bytes: int
    decompressed_body_bytes: int
    timings: TransportTimings
    budget_usage: ScanBudgetUsage


class _ResponseReader:
    def __init__(
        self,
        connection: socket.socket,
        budget: ScanBudget,
        request_deadline: float,
        first_byte_deadline: float,
    ) -> None:
        self._connection = connection
        self._budget = budget
        self._request_deadline = request_deadline
        self._first_byte_deadline = first_byte_deadline
        self._buffer = bytearray()
        self._received_first_byte = False
        self.first_byte_at: float | None = None
        self.transferred_bytes = 0

    def read_line(self) -> bytes:
        while True:
            newline = self._buffer.find(b"\n")
            if newline >= 0:
                line_size = newline + 1
                if line_size > MAX_HEADER_LINE_BYTES:
                    raise _BudgetExceeded()
                line = bytes(self._buffer[:line_size])
                del self._buffer[:line_size]
                if not line.endswith(b"\r\n") or b"\r" in line[:-2] or b"\n" in line[:-2]:
                    raise InvalidHttpResponse()
                return line
            if len(self._buffer) >= MAX_HEADER_LINE_BYTES:
                raise _BudgetExceeded()
            self._receive(min(4096, MAX_HEADER_LINE_BYTES - len(self._buffer)))

    def read_exact(self, byte_count: int) -> bytes:
        if byte_count < 0:
            raise InvalidHttpResponse()
        while len(self._buffer) < byte_count:
            self._receive(min(4096, byte_count - len(self._buffer)))
        result = bytes(self._buffer[:byte_count])
        del self._buffer[:byte_count]
        return result

    def reject_buffered_trailing_bytes(self) -> None:
        if self._buffer:
            raise InvalidHttpResponse()

    def read_body_into(self, body: bytearray, byte_count: int) -> None:
        remaining = byte_count
        while remaining:
            chunk = self.read_exact(min(4096, remaining))
            if len(body) + len(chunk) > MAX_ENCODED_BODY_BYTES:
                raise _BudgetExceeded()
            if len(body) + len(chunk) > MAX_DECOMPRESSED_BODY_BYTES:
                raise _BudgetExceeded()
            self._budget.charge_identity(len(chunk))
            body.extend(chunk)
            remaining -= len(chunk)

    def _receive(self, maximum: int) -> None:
        now = time.monotonic()
        if now >= self._request_deadline:
            raise _DeadlineExpired()
        if self._received_first_byte:
            phase_deadline = min(
                self._request_deadline,
                now + READ_INACTIVITY_TIMEOUT_SECONDS,
            )
        else:
            phase_deadline = min(self._request_deadline, self._first_byte_deadline)
        remaining = phase_deadline - now
        if remaining <= 0:
            if now >= self._request_deadline:
                raise _DeadlineExpired()
            raise PinnedHttpError(TransportFailure.CONNECTION_REFUSED_OR_TIMED_OUT)

        self._connection.settimeout(remaining)
        try:
            data = self._connection.recv(maximum)
        except (socket.timeout, TimeoutError):
            if time.monotonic() >= self._request_deadline:
                raise _DeadlineExpired() from None
            raise PinnedHttpError(
                TransportFailure.CONNECTION_REFUSED_OR_TIMED_OUT
            ) from None
        except OSError:
            raise PinnedHttpError(
                TransportFailure.CONNECTION_REFUSED_OR_TIMED_OUT
            ) from None
        if time.monotonic() >= phase_deadline:
            if time.monotonic() >= self._request_deadline:
                raise _DeadlineExpired()
            raise PinnedHttpError(TransportFailure.CONNECTION_REFUSED_OR_TIMED_OUT)
        if not data:
            raise InvalidHttpResponse()

        self._received_first_byte = True
        if self.first_byte_at is None:
            self.first_byte_at = time.monotonic()
        self.transferred_bytes += len(data)
        self._budget.charge_transferred(len(data))
        if self.transferred_bytes > MAX_RESPONSE_TRANSFERRED_BYTES:
            raise _BudgetExceeded()
        self._buffer.extend(data)


@dataclass(slots=True)
class _HeaderAccounting:
    total_bytes: int = 0
    field_count: int = 0

    def add_line(self, line: bytes, *, field: bool) -> None:
        if len(line) > MAX_HEADER_LINE_BYTES:
            raise _BudgetExceeded()
        self.total_bytes += len(line)
        if self.total_bytes > MAX_RESPONSE_HEADER_BYTES:
            raise _BudgetExceeded()
        if field:
            self.field_count += 1
            if self.field_count > MAX_RESPONSE_HEADERS:
                raise _BudgetExceeded()


class PinnedHttpTransport:
    """Send one fixed-header request to one validated address, without retries or pooling."""

    def get(
        self,
        resolution: ValidatedResolution,
        *,
        scheme: str,
        budget: ScanBudget,
        address_family: AddressFamily | str | None = None,
    ) -> PinnedHttpResponse:
        return self.request(
            resolution,
            scheme=scheme,
            method="GET",
            budget=budget,
            address_family=address_family,
        )

    def head(
        self,
        resolution: ValidatedResolution,
        *,
        scheme: str,
        budget: ScanBudget,
        address_family: AddressFamily | str | None = None,
    ) -> PinnedHttpResponse:
        return self.request(
            resolution,
            scheme=scheme,
            method="HEAD",
            budget=budget,
            address_family=address_family,
        )

    def request(
        self,
        resolution: ValidatedResolution,
        *,
        scheme: str,
        method: str,
        budget: ScanBudget,
        address_family: AddressFamily | str | None = None,
    ) -> PinnedHttpResponse:
        if scheme not in ("http", "https") or method not in ("GET", "HEAD"):
            raise ValueError("unsupported_outbound_request")
        if type(budget) is not ScanBudget:
            raise ValueError("invalid_scan_budget")
        _validate_resolution(resolution)
        selected_address = _select_address(resolution, address_family)
        port = 80 if scheme == "http" else 443

        started = time.monotonic()
        budget.begin_request()
        request_deadline = min(started + HTTP_REQUEST_TIMEOUT_SECONDS, budget.deadline)
        if started >= request_deadline:
            raise _DeadlineExpired()

        raw_socket: socket.socket | None = None
        active_socket: socket.socket | ssl.SSLSocket | None = None
        try:
            try:
                raw_socket = self._new_socket(selected_address)
            except OSError:
                raise PinnedHttpError(
                    TransportFailure.CONNECTION_REFUSED_OR_TIMED_OUT
                ) from None
            active_socket = raw_socket
            connect_deadline = min(
                started + TCP_CONNECT_TIMEOUT_SECONDS,
                request_deadline,
            )
            self._set_timeout(raw_socket, connect_deadline, request_deadline)
            try:
                self._connect(raw_socket, selected_address, port)
            except (socket.timeout, TimeoutError):
                if time.monotonic() >= request_deadline:
                    raise _DeadlineExpired() from None
                raise PinnedHttpError(
                    TransportFailure.CONNECTION_REFUSED_OR_TIMED_OUT
                ) from None
            except OSError:
                raise PinnedHttpError(
                    TransportFailure.CONNECTION_REFUSED_OR_TIMED_OUT
                ) from None
            self._check_late(connect_deadline, request_deadline)
            connected = time.monotonic()

            tls_seconds = 0.0
            if scheme == "https":
                tls_start = time.monotonic()
                tls_deadline = min(
                    tls_start + TLS_HANDSHAKE_TIMEOUT_SECONDS,
                    request_deadline,
                )
                self._set_timeout(raw_socket, tls_deadline, request_deadline)
                try:
                    context = self._tls_context()
                    if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
                        raise PinnedHttpError(TransportFailure.TLS_VERIFICATION_FAILED)
                    context.set_alpn_protocols(["http/1.1"])
                except PinnedHttpError:
                    raise
                except (OSError, ssl.SSLError, NotImplementedError):
                    raise PinnedHttpError(
                        TransportFailure.TLS_VERIFICATION_FAILED
                    ) from None
                self._set_timeout(raw_socket, tls_deadline, request_deadline)
                try:
                    tls_socket = self._wrap_tls(
                        raw_socket,
                        context,
                        resolution.hostname,
                    )
                except (ssl.SSLError, OSError, TimeoutError):
                    if time.monotonic() >= request_deadline:
                        raise _DeadlineExpired() from None
                    raise PinnedHttpError(
                        TransportFailure.TLS_VERIFICATION_FAILED
                    ) from None
                active_socket = tls_socket
                self._check_late(tls_deadline, request_deadline)
                if tls_socket.selected_alpn_protocol() != "http/1.1":
                    raise PinnedHttpError(TransportFailure.TLS_VERIFICATION_FAILED)
                tls_seconds = time.monotonic() - tls_start

            request_bytes = (
                f"{method} / HTTP/1.1\r\n"
                f"Host: {resolution.hostname}\r\n"
                "Accept-Encoding: identity\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode("ascii")
            self._set_timeout(active_socket, request_deadline, request_deadline)
            try:
                active_socket.sendall(request_bytes)
            except (socket.timeout, TimeoutError):
                if time.monotonic() >= request_deadline:
                    raise _DeadlineExpired() from None
                raise PinnedHttpError(
                    TransportFailure.CONNECTION_REFUSED_OR_TIMED_OUT
                ) from None
            except OSError:
                raise PinnedHttpError(
                    TransportFailure.CONNECTION_REFUSED_OR_TIMED_OUT
                ) from None
            self._check_late(request_deadline, request_deadline)

            response_started = time.monotonic()
            first_byte_deadline = min(
                response_started + FIRST_BYTE_TIMEOUT_SECONDS,
                request_deadline,
            )
            reader = _ResponseReader(
                active_socket,
                budget,
                request_deadline,
                first_byte_deadline,
            )
            parse_started = time.monotonic()
            parsed = _parse_response(reader, method)
            self._close_socket(active_socket)
            active_socket = None
            raw_socket = None
            self._check_late(request_deadline, request_deadline)
            finished = time.monotonic()

            result = PinnedHttpResponse(
                hostname=str(resolution.hostname),
                destination_ip=selected_address.address,
                scheme=scheme,
                port=port,
                method=method,
                status_code=parsed.status_code,
                reason=parsed.reason,
                headers=parsed.headers,
                trailers=parsed.trailers,
                is_redirect=300 <= parsed.status_code < 400 and parsed.status_code != 304,
                redirect_location=_redirect_location(parsed.status_code, parsed.headers),
                body=bytes(parsed.body),
                response_transferred_bytes=reader.transferred_bytes,
                encoded_body_bytes=len(parsed.body),
                decompressed_body_bytes=len(parsed.body),
                timings=TransportTimings(
                    connect_seconds=connected - started,
                    tls_seconds=tls_seconds,
                    first_byte_seconds=max(
                        0.0,
                        (reader.first_byte_at or response_started) - response_started,
                    ),
                    response_read_seconds=max(0.0, finished - parse_started),
                    total_seconds=finished - started,
                ),
                budget_usage=budget.usage(),
            )
            self._check_late(request_deadline, request_deadline)
            return result
        finally:
            if active_socket is not None:
                self._close_socket(active_socket)
            elif raw_socket is not None:
                self._close_socket(raw_socket)

    def _new_socket(self, address: CanonicalAddress) -> socket.socket:
        family = socket.AF_INET if address.family is AddressFamily.IPV4 else socket.AF_INET6
        return socket.socket(family, socket.SOCK_STREAM)

    @staticmethod
    def _connect(
        connection: socket.socket,
        address: CanonicalAddress,
        port: int,
    ) -> None:
        if address.family is AddressFamily.IPV4:
            connection.connect((address.address, port))
        else:
            connection.connect((address.address, port, 0, 0))

    @staticmethod
    def _tls_context() -> ssl.SSLContext:
        return ssl.create_default_context()

    @staticmethod
    def _wrap_tls(
        connection: socket.socket,
        context: ssl.SSLContext,
        hostname: str,
    ) -> ssl.SSLSocket:
        return context.wrap_socket(
            connection,
            server_hostname=hostname,
            do_handshake_on_connect=True,
        )

    @staticmethod
    def _set_timeout(
        connection: socket.socket | ssl.SSLSocket,
        phase_deadline: float,
        request_deadline: float,
    ) -> None:
        now = time.monotonic()
        if now >= request_deadline:
            raise _DeadlineExpired()
        timeout = min(phase_deadline, request_deadline) - now
        if timeout <= 0:
            raise PinnedHttpError(TransportFailure.CONNECTION_REFUSED_OR_TIMED_OUT)
        connection.settimeout(timeout)

    @staticmethod
    def _check_late(phase_deadline: float, request_deadline: float) -> None:
        now = time.monotonic()
        if now >= request_deadline:
            raise _DeadlineExpired()
        if now >= phase_deadline:
            raise PinnedHttpError(TransportFailure.CONNECTION_REFUSED_OR_TIMED_OUT)

    @staticmethod
    def _close_socket(connection: socket.socket | ssl.SSLSocket) -> None:
        try:
            connection.close()
        except OSError:
            raise PinnedHttpError(
                TransportFailure.CONNECTION_REFUSED_OR_TIMED_OUT
            ) from None


@dataclass(frozen=True, slots=True)
class _ParsedResponse:
    status_code: int
    reason: str
    headers: tuple[HttpHeader, ...]
    trailers: tuple[HttpHeader, ...]
    body: bytearray


def _parse_response(
    reader: _ResponseReader,
    method: str,
) -> _ParsedResponse:
    accounting = _HeaderAccounting()
    while True:
        status_line = reader.read_line()
        accounting.add_line(status_line, field=False)
        status_code, reason = _parse_status_line(status_line[:-2])
        raw_headers: list[HttpHeader] = []
        while True:
            line = reader.read_line()
            accounting.add_line(line, field=bool(line != b"\r\n"))
            if line == b"\r\n":
                break
            raw_headers.append(_parse_header(line[:-2]))

        _validate_header_fields(raw_headers)
        content_length, chunked = _framing(raw_headers)
        content_encoding = _content_encoding(raw_headers)
        del content_encoding

        if 100 <= status_code < 200:
            if status_code == 101 or content_length is not None or chunked:
                raise InvalidHttpResponse()
            continue

        bodyless = method == "HEAD" or status_code in (204, 205, 304)
        if bodyless and status_code == 204 and (content_length is not None or chunked):
            raise InvalidHttpResponse()
        if status_code == 205 and content_length not in (None, 0):
            raise InvalidHttpResponse()
        if content_length is not None and content_length > MAX_ENCODED_BODY_BYTES:
            raise _BudgetExceeded()

        body = bytearray()
        trailers: list[HttpHeader] = []
        if status_code == 205 and chunked:
            _read_chunked_body(reader, body, accounting, raw_headers, trailers)
            if body:
                raise InvalidHttpResponse()
        elif not bodyless:
            if chunked:
                _read_chunked_body(reader, body, accounting, raw_headers, trailers)
            elif content_length is not None:
                reader.read_body_into(body, content_length)
            else:
                raise InvalidHttpResponse()
        reader.reject_buffered_trailing_bytes()

        return _ParsedResponse(
            status_code=status_code,
            reason=reason,
            headers=tuple(raw_headers),
            trailers=tuple(trailers),
            body=body,
        )


def _parse_status_line(line: bytes) -> tuple[int, str]:
    if (
        len(line) < 13
        or line[:8] != b"HTTP/1.1"
        or line[8:9] != b" "
        or line[12:13] != b" "
        or any(byte < 48 or byte > 57 for byte in line[9:12])
    ):
        raise InvalidHttpResponse()
    reason = line[13:]
    if any((byte < 32 and byte != 9) or byte == 127 for byte in reason):
        raise InvalidHttpResponse()
    status_code = int(line[9:12])
    if not 100 <= status_code <= 599:
        raise InvalidHttpResponse()
    return status_code, reason.decode("latin-1")


def _parse_header(line: bytes) -> HttpHeader:
    if not line or line[:1] in (b" ", b"\t"):
        raise InvalidHttpResponse()
    separator = line.find(b":")
    if separator <= 0:
        raise InvalidHttpResponse()
    name = line[:separator]
    if any(byte not in _HEADER_TOKEN for byte in name):
        raise InvalidHttpResponse()
    raw_value = line[separator + 1 :].strip(b" \t")
    if any((byte < 32 and byte != 9) or byte == 127 for byte in raw_value):
        raise InvalidHttpResponse()
    return HttpHeader(name.decode("ascii").lower(), raw_value.decode("latin-1"))


def _validate_header_fields(headers: list[HttpHeader]) -> None:
    for header in headers:
        if header.name in {"content-length", "transfer-encoding"} and not header.value:
            raise InvalidHttpResponse()


def _field_values(headers: list[HttpHeader], name: str) -> list[str]:
    return [header.value for header in headers if header.name == name]


def _framing(headers: list[HttpHeader]) -> tuple[int | None, bool]:
    lengths = _field_values(headers, "content-length")
    transfer_encodings = _field_values(headers, "transfer-encoding")
    if len(lengths) > 1 or len(transfer_encodings) > 1:
        raise InvalidHttpResponse()
    if lengths and transfer_encodings:
        raise InvalidHttpResponse()

    content_length: int | None = None
    if lengths:
        value = lengths[0]
        if not value or any(character < "0" or character > "9" for character in value):
            raise InvalidHttpResponse()
        try:
            content_length = int(value)
        except ValueError:
            raise InvalidHttpResponse() from None
        if content_length > 2**63 - 1:
            raise InvalidHttpResponse()

    chunked = bool(transfer_encodings)
    if chunked and transfer_encodings[0] != "chunked":
        raise InvalidHttpResponse()
    return content_length, chunked


def _content_encoding(headers: list[HttpHeader]) -> str | None:
    encodings = _field_values(headers, "content-encoding")
    if not encodings:
        return None
    if len(encodings) != 1 or encodings[0] != "identity":
        raise InvalidHttpResponse()
    return encodings[0]


def _read_chunked_body(
    reader: _ResponseReader,
    body: bytearray,
    accounting: _HeaderAccounting,
    headers: list[HttpHeader],
    trailers: list[HttpHeader],
) -> None:
    while True:
        size_line = reader.read_line()
        size_text = size_line[:-2]
        if not size_text or any(
            byte not in b"0123456789abcdefABCDEF" for byte in size_text
        ):
            raise InvalidHttpResponse()
        if len(size_text) > 16:
            raise InvalidHttpResponse()
        size = int(size_text, 16)
        if size > MAX_ENCODED_BODY_BYTES - len(body):
            raise _BudgetExceeded()
        if size == 0:
            break
        reader.read_body_into(body, size)
        if reader.read_exact(2) != b"\r\n":
            raise InvalidHttpResponse()

    existing_names = {header.name for header in headers}
    trailer_names: set[str] = set()
    while True:
        line = reader.read_line()
        accounting.add_line(line, field=bool(line != b"\r\n"))
        if line == b"\r\n":
            return
        trailer = _parse_header(line[:-2])
        if (
            trailer.name in _TRAILER_FORBIDDEN
            or trailer.name in existing_names
            or trailer.name in trailer_names
        ):
            raise InvalidHttpResponse()
        trailer_names.add(trailer.name)
        trailers.append(trailer)


def _redirect_location(status_code: int, headers: tuple[HttpHeader, ...]) -> str | None:
    if not 300 <= status_code < 400 or status_code == 304:
        return None
    locations = [header.value for header in headers if header.name == "location"]
    return locations[0] if len(locations) == 1 else None


def _validate_resolution(resolution: ValidatedResolution) -> None:
    if type(resolution) is not ValidatedResolution:
        raise PinnedHttpError(TransportFailure.TARGET_ADDRESS_UNAVAILABLE)
    try:
        if (
            resolution.policy_version != POLICY_VERSION
            or type(resolution.status) is not ResolutionStatus
            or resolution.status is not ResolutionStatus.VALID
            or type(resolution.hostname) is not CanonicalHostname
            or type(resolution.terminal_owner) is not CanonicalHostname
            or type(resolution.a_family) is not FamilyResolution
            or type(resolution.aaaa_family) is not FamilyResolution
        ):
            raise ValueError
        ipv4 = tuple(resolution.ipv4_addresses)
        ipv6 = tuple(resolution.ipv6_addresses)
        if not ipv4 and not ipv6:
            raise ValueError
        for expected_family, addresses in (
            (AddressFamily.IPV4, ipv4),
            (AddressFamily.IPV6, ipv6),
        ):
            for record in addresses:
                if type(record) is not CanonicalAddress or record.family is not expected_family:
                    raise ValueError
                result = classify_ip_address(record.address)
                if (
                    result.decision is not ClassificationDecision.ALLOW
                    or result.canonical_address != record.address
                ):
                    raise ValueError
        rebuilt = ValidatedResolution(
            hostname=resolution.hostname,
            ipv4_addresses=ipv4,
            ipv6_addresses=ipv6,
            cname_chain=resolution.cname_chain,
            terminal_owner=resolution.terminal_owner,
            resolved_at=resolution.resolved_at,
            total_deadline=resolution.total_deadline,
            policy_version=resolution.policy_version,
            family_results=(resolution.a_family, resolution.aaaa_family),
        )
        if rebuilt != resolution:
            raise ValueError
    except (AttributeError, TypeError, ValueError):
        raise PinnedHttpError(TransportFailure.TARGET_ADDRESS_UNAVAILABLE) from None


def _select_address(
    resolution: ValidatedResolution,
    address_family: AddressFamily | str | None,
) -> CanonicalAddress:
    if address_family is None:
        candidates = (*resolution.ipv4_addresses, *resolution.ipv6_addresses)
    else:
        try:
            family = AddressFamily(address_family)
        except (TypeError, ValueError):
            raise ValueError("unsupported_address_family") from None
        candidates = (
            resolution.ipv4_addresses
            if family is AddressFamily.IPV4
            else resolution.ipv6_addresses
        )
    if not candidates:
        raise PinnedHttpError(TransportFailure.TARGET_ADDRESS_UNAVAILABLE)
    selected = candidates[0]
    if selected not in (*resolution.ipv4_addresses, *resolution.ipv6_addresses):
        raise PinnedHttpError(TransportFailure.TARGET_ADDRESS_UNAVAILABLE)
    try:
        parsed = ipaddress.ip_address(selected.address)
    except ValueError:
        raise PinnedHttpError(TransportFailure.TARGET_ADDRESS_UNAVAILABLE) from None
    expected_version = 4 if selected.family is AddressFamily.IPV4 else 6
    if parsed.version != expected_version:
        raise PinnedHttpError(TransportFailure.TARGET_ADDRESS_UNAVAILABLE)
    return selected
