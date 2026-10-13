"""Opt-in, single-invocation sequencing for clients using dispatch reservations.

This helper is not an egress proxy or a provider-usage meter. The supplied transport
must itself have automatic retries and redirects disabled if one invocation must
correspond to one HTTP request.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from math import ceil
from typing import Any, Generic, Protocol, TypeVar
from urllib.error import HTTPError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class DispatchHttpResponse(Protocol):
    """The response metadata that may be stored as a client-reported receipt."""

    status_code: int


@dataclass(frozen=True, slots=True)
class DispatchReservation:
    dispatch_attempt_id: str
    created: bool


class DispatchLedger(Protocol):
    """Adapter for the coordination API's reservation and receipt endpoints."""

    def reserve_dispatch_attempt(
        self,
        *,
        task_id: str,
        claim_fencing_token: int,
        resource_fencing_tokens: Mapping[str, int],
        idempotency_key: str,
    ) -> DispatchReservation: ...

    def record_dispatch_attempt_receipt(
        self,
        *,
        task_id: str,
        dispatch_attempt_id: str,
        claim_fencing_token: int,
        http_status_code: int,
        retry_after_seconds: int | None,
    ) -> None: ...


class DispatchLedgerError(RuntimeError):
    """Sanitized coordination API failure; never includes response bodies or URLs."""


class DispatchLedgerHttpError(DispatchLedgerError):
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        super().__init__(f"coordination API returned HTTP {status_code}")


class DispatchLedgerTransportError(DispatchLedgerError):
    def __init__(self, failure_type: str) -> None:
        self.failure_type = failure_type
        super().__init__(f"coordination transport failed ({failure_type})")


class DispatchLedgerProtocolError(DispatchLedgerError):
    def __init__(self, failure_type: str = "invalid_response") -> None:
        self.failure_type = failure_type
        super().__init__(f"coordination API returned an invalid response ({failure_type})")


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


class _JsonResponse(Protocol):
    status: int

    def read(self, amount: int = -1) -> bytes: ...

    def close(self) -> None: ...


class _JsonOpener(Protocol):
    def open(self, request: Request, timeout: float) -> _JsonResponse: ...


_MAX_COORDINATION_RESPONSE_BYTES = 1_048_576


class CoordinationHttpDispatchLedger:
    """HTTP adapter for this service's dispatch reservation and receipt routes.

    The default urllib opener refuses redirects and does not retry requests. A
    custom opener is intended for tests and must preserve those properties.
    """

    def __init__(
        self,
        *,
        base_url: str,
        bearer_token: str,
        timeout_seconds: float = 10.0,
        opener: _JsonOpener | None = None,
    ) -> None:
        parsed = urlsplit(base_url)
        try:
            _ = parsed.port
        except ValueError:
            raise ValueError("base_url must contain a valid port") from None
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "base_url must be an http(s) URL without credentials, query, or fragment"
            )
        if parsed.scheme == "http" and not _is_loopback_host(parsed.hostname):
            raise ValueError("plain HTTP is allowed only for loopback coordination servers")
        if not bearer_token or any(not 0x21 <= ord(char) <= 0x7E for char in bearer_token):
            raise ValueError("bearer_token must contain only visible ASCII characters")
        if type(timeout_seconds) not in {int, float} or not 0 < timeout_seconds <= 300:
            raise ValueError("timeout_seconds must be greater than 0 and at most 300")

        self._base_url = base_url.rstrip("/")
        self._bearer_token = bearer_token
        self._timeout_seconds = float(timeout_seconds)
        self._opener = opener or build_opener(_NoRedirectHandler())

    def reserve_dispatch_attempt(
        self,
        *,
        task_id: str,
        claim_fencing_token: int,
        resource_fencing_tokens: Mapping[str, int],
        idempotency_key: str,
    ) -> DispatchReservation:
        payload = self._post_json(
            f"/v1/tasks/{quote(task_id, safe='')}/dispatch-attempts",
            {
                "claim_fencing_token": claim_fencing_token,
                "resource_fencing_tokens": dict(resource_fencing_tokens),
                "idempotency_key": idempotency_key,
            },
            expected_status=201,
        )
        try:
            reservation = payload["reservation"]
            attempt_id = reservation["id"]
            created = payload["created"]
        except (KeyError, TypeError):
            raise DispatchLedgerProtocolError() from None
        if not isinstance(attempt_id, str) or not attempt_id or type(created) is not bool:
            raise DispatchLedgerProtocolError()
        return DispatchReservation(dispatch_attempt_id=attempt_id, created=created)

    def record_dispatch_attempt_receipt(
        self,
        *,
        task_id: str,
        dispatch_attempt_id: str,
        claim_fencing_token: int,
        http_status_code: int,
        retry_after_seconds: int | None,
    ) -> None:
        payload = self._post_json(
            f"/v1/tasks/{quote(task_id, safe='')}/dispatch-attempts/"
            f"{quote(dispatch_attempt_id, safe='')}/receipt",
            {
                "claim_fencing_token": claim_fencing_token,
                "http_status_code": http_status_code,
                "retry_after_seconds": retry_after_seconds,
            },
            expected_status=200,
        )
        try:
            receipt = payload["receipt"]
            returned_attempt_id = receipt["dispatch_attempt_id"]
            created = payload["created"]
        except (KeyError, TypeError):
            raise DispatchLedgerProtocolError() from None
        if returned_attempt_id != dispatch_attempt_id or type(created) is not bool:
            raise DispatchLedgerProtocolError()

    def _post_json(
        self, path: str, payload: Mapping[str, Any], *, expected_status: int
    ) -> dict[str, Any]:
        request = Request(
            f"{self._base_url}{path}",
            data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self._bearer_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        try:
            response = self._opener.open(request, timeout=self._timeout_seconds)
        except HTTPError as exc:
            error = DispatchLedgerHttpError(exc.code)
        except Exception as exc:
            error = DispatchLedgerTransportError(_safe_failure_type(exc))
        else:
            error = None
        if error is not None:
            raise error

        read_error: DispatchLedgerError | None = None
        try:
            status_code = response.status
            if type(status_code) is not int:
                raise DispatchLedgerProtocolError()
            if status_code != expected_status:
                raise DispatchLedgerHttpError(status_code)
            response_body = response.read(_MAX_COORDINATION_RESPONSE_BYTES + 1)
        except DispatchLedgerError:
            raise
        except Exception as exc:
            read_error = DispatchLedgerTransportError(_safe_failure_type(exc))
        finally:
            try:
                response.close()
            except Exception:
                # The response is already consumed or unusable; do not expose
                # implementation-specific close errors or alter the API result.
                pass
        if read_error is not None:
            raise read_error

        if len(response_body) > _MAX_COORDINATION_RESPONSE_BYTES:
            raise DispatchLedgerProtocolError("response_too_large")
        try:
            decoded = json.loads(response_body)
        except Exception as exc:
            error = DispatchLedgerProtocolError(_safe_failure_type(exc))
        else:
            error = None
        if error is not None:
            raise error
        if not isinstance(decoded, dict):
            raise DispatchLedgerProtocolError()
        return decoded


class DispatchReservationReplay(RuntimeError):
    """Raised when the idempotency key already has a reservation; no send is made."""

    def __init__(self, dispatch_attempt_id: str) -> None:
        self.dispatch_attempt_id = dispatch_attempt_id
        super().__init__("dispatch reservation was replayed; provider send was not attempted")


class DispatchReservationInvalid(RuntimeError):
    """Raised when a ledger adapter returns an unusable reservation."""


class DispatchResponseInvalid(RuntimeError):
    """Raised after one send invocation when response metadata cannot be receipted."""

    def __init__(self, dispatch_attempt_id: str, failure_type: str = "invalid_response") -> None:
        self.dispatch_attempt_id = dispatch_attempt_id
        self.failure_type = failure_type
        super().__init__("response metadata is invalid; dispatch reservation remains consumed")


class DispatchOutcomeUnknown(RuntimeError):
    """The send raised after invocation, so whether the provider received it is unknown."""

    def __init__(self, dispatch_attempt_id: str, failure_type: str = "send_failure") -> None:
        self.dispatch_attempt_id = dispatch_attempt_id
        self.failure_type = failure_type
        super().__init__("dispatch outcome is unknown; this attempt will not be retried")


class DispatchReceiptUnrecorded(RuntimeError):
    """A response was received, but its client-reported receipt was not confirmed."""

    def __init__(
        self, dispatch_attempt_id: str, http_status_code: int, failure_type: str = "receipt_failure"
    ) -> None:
        self.dispatch_attempt_id = dispatch_attempt_id
        self.http_status_code = http_status_code
        self.failure_type = failure_type
        super().__init__("receipt was not confirmed; do not resend the provider request")


ResponseT = TypeVar("ResponseT", bound=DispatchHttpResponse)


@dataclass(frozen=True, slots=True)
class DispatchResult(Generic[ResponseT]):
    dispatch_attempt_id: str
    response: ResponseT


def dispatch_once(
    *,
    ledger: DispatchLedger,
    task_id: str,
    claim_fencing_token: int,
    resource_fencing_tokens: Mapping[str, int],
    idempotency_key: str,
    send_once: Callable[[], ResponseT],
) -> DispatchResult[ResponseT]:
    """Reserve, invoke the supplied transport once, and record its response metadata.

    Reservation errors propagate before the transport is called. An idempotent
    reservation replay is refused because the first caller may have sent already.
    A failed or ambiguous send consumes the reservation and is never retried here.
    A 429 is only recorded; retry policy remains an explicit caller decision.
    """

    reservation = ledger.reserve_dispatch_attempt(
        task_id=task_id,
        claim_fencing_token=claim_fencing_token,
        resource_fencing_tokens=dict(resource_fencing_tokens),
        idempotency_key=idempotency_key,
    )
    if not isinstance(reservation.dispatch_attempt_id, str) or not reservation.dispatch_attempt_id:
        raise DispatchReservationInvalid("ledger returned an empty dispatch attempt identity")
    if reservation.created is not True:
        raise DispatchReservationReplay(reservation.dispatch_attempt_id)

    try:
        response = send_once()
    except Exception as exc:
        error = DispatchOutcomeUnknown(reservation.dispatch_attempt_id, _safe_failure_type(exc))
    else:
        error = None
    if error is not None:
        raise error

    try:
        status_code = response.status_code
        retry_after_seconds = _retry_after_seconds(response)
    except Exception as exc:
        error = DispatchResponseInvalid(reservation.dispatch_attempt_id, _safe_failure_type(exc))
    else:
        error = None
    if error is not None:
        raise error
    if (
        type(status_code) is not int
        or not 100 <= status_code <= 599
        or (
            retry_after_seconds is not None
            and (type(retry_after_seconds) is not int or not 0 <= retry_after_seconds <= 86_400)
        )
    ):
        raise DispatchResponseInvalid(reservation.dispatch_attempt_id)

    try:
        ledger.record_dispatch_attempt_receipt(
            task_id=task_id,
            dispatch_attempt_id=reservation.dispatch_attempt_id,
            claim_fencing_token=claim_fencing_token,
            http_status_code=status_code,
            retry_after_seconds=retry_after_seconds,
        )
    except Exception as exc:
        error = DispatchReceiptUnrecorded(
            reservation.dispatch_attempt_id, status_code, _safe_failure_type(exc)
        )
    else:
        error = None
    if error is not None:
        raise error

    return DispatchResult(dispatch_attempt_id=reservation.dispatch_attempt_id, response=response)


def _retry_after_seconds(response: DispatchHttpResponse) -> int | None:
    """Normalize numeric Retry-After headers used by standard HTTP clients."""

    try:
        explicit = getattr(response, "retry_after_seconds", None)
    except AttributeError:
        explicit = None
    except Exception:
        return None
    if explicit is not None:
        return _bounded_retry_after(explicit)

    try:
        headers = getattr(response, "headers", None)
        if headers is None:
            return None
        retry_after = headers.get("Retry-After")
        if retry_after is None:
            retry_after = headers.get("retry-after")
        if retry_after is None:
            retry_after = next(
                (
                    value
                    for name, value in headers.items()
                    if isinstance(name, str) and name.casefold() == "retry-after"
                ),
                None,
            )
    except Exception:
        return None
    return _bounded_retry_after(retry_after)


def _bounded_retry_after(value: object) -> int | None:
    if value is None:
        return None
    if type(value) is int:
        return value if 0 <= value <= 86_400 else None
    if not isinstance(value, str):
        return None

    text = value.strip()
    if text.isascii() and text.isdigit():
        try:
            return _bounded_retry_after(int(text))
        except ValueError:
            return None
    try:
        retry_at = parsedate_to_datetime(text)
        if retry_at.tzinfo is None:
            retry_at = retry_at.replace(tzinfo=UTC)
        seconds = max(0, ceil((retry_at - datetime.now(UTC)).total_seconds()))
        return _bounded_retry_after(seconds)
    except (TypeError, ValueError, OverflowError):
        return None


def _safe_failure_type(exc: Exception) -> str:
    name = type(exc).__name__
    if name.isascii() and name.isidentifier() and len(name) <= 64:
        return name
    return "Exception"


def _is_loopback_host(hostname: str | None) -> bool:
    if hostname is None:
        return False
    if hostname == "localhost" or hostname.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


__all__ = [
    "DispatchHttpResponse",
    "DispatchLedger",
    "CoordinationHttpDispatchLedger",
    "DispatchLedgerError",
    "DispatchLedgerHttpError",
    "DispatchLedgerProtocolError",
    "DispatchLedgerTransportError",
    "DispatchReservation",
    "DispatchReservationInvalid",
    "DispatchReservationReplay",
    "DispatchResponseInvalid",
    "DispatchOutcomeUnknown",
    "DispatchReceiptUnrecorded",
    "DispatchResult",
    "dispatch_once",
]
