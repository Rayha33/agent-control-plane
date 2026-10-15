"""Opt-in, single-invocation sequencing for clients using dispatch reservations.

This helper is not an egress proxy or a provider-usage meter. The supplied transport
must itself have automatic retries and redirects disabled if one invocation must
correspond to one HTTP request.
"""

from __future__ import annotations

import ipaddress
import json
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from math import ceil
from typing import Any, Generic, Literal, Protocol, TypeVar
from urllib.error import HTTPError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .coordination_schemas import ProviderUsageReport
from .provider_usage import (
    ClientReportedProviderUsage,
    _provider_usage_extraction_failed,
    parse_anthropic_messages_usage,
    parse_gemini_generate_content_usage,
    parse_openai_responses_usage,
)


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
        provider_usage_report: Mapping[str, Any] | None = None,
    ) -> None: ...


class DispatchLedgerError(RuntimeError):
    """Sanitized coordination API failure; never includes response bodies or URLs."""


class DispatchLedgerHttpError(DispatchLedgerError):
    def __init__(self, status_code: int, error_code: str | None = None) -> None:
        self.status_code = status_code
        self.error_code = _safe_api_error_code(error_code)
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


class _ProviderHttpResponse(_JsonResponse, Protocol):
    headers: Any


class _ProviderHttpOpener(Protocol):
    def open(self, request: Request, timeout: float) -> _ProviderHttpResponse: ...


_MAX_COORDINATION_RESPONSE_BYTES = 1_048_576
_MAX_COORDINATION_ERROR_BYTES = 16_384
_MAX_OPENAI_RESPONSES_BYTES = 16_777_216
_MAX_PROVIDER_RESPONSE_BYTES = 16_777_216
_OPENAI_RESPONSES_URL = "https://api.openai.com/v1/responses"
_ANTHROPIC_MESSAGES_URL = "https://api.anthropic.com/v1/messages"
_GEMINI_GENERATE_CONTENT_URL = "https://generativelanguage.googleapis.com/v1beta/models/"
_ANTHROPIC_API_VERSION = "2023-06-01"


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
        provider_usage_report: Mapping[str, Any] | None = None,
    ) -> None:
        request_payload: dict[str, Any] = {
            "claim_fencing_token": claim_fencing_token,
            "http_status_code": http_status_code,
            "retry_after_seconds": retry_after_seconds,
        }
        if provider_usage_report is not None:
            request_payload["provider_usage_report"] = dict(provider_usage_report)
        payload = self._post_json(
            f"/v1/tasks/{quote(task_id, safe='')}/dispatch-attempts/"
            f"{quote(dispatch_attempt_id, safe='')}/receipt",
            request_payload,
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

    def record_budget_interruption_report(
        self, *, task_id: str, request: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Record and verify one bounded, client-reported interruption checkpoint.

        This is a one-shot cooperative API call. A successful response is still
        client testimony, not a host-verified checkpoint or promotable result.
        """
        import hashlib

        from .coordination_schemas import (
            BudgetInterruptionReportCreate,
            BudgetInterruptionReportResult,
        )

        try:
            request_model = BudgetInterruptionReportCreate.model_validate(request)
        except Exception:
            # Validation details may quote the caller's checkpoint. Keep them
            # out of logs and exceptions, especially for rejected secret-shaped
            # values.
            raise ValueError("invalid interruption report request") from None
        request_payload = request_model.model_dump(mode="json")
        payload = self._post_json(
            f"/v1/tasks/{quote(task_id, safe='')}/interruption-reports",
            request_payload,
            expected_status=201,
        )

        def has_exact_int_values(value: object) -> bool:
            return isinstance(value, dict) and all(
                type(key) is str and type(item) is int for key, item in value.items()
            )

        raw_report = payload.get("report")
        if (
            type(payload.get("created")) is not bool
            or not isinstance(raw_report, dict)
            or type(raw_report.get("claim_fencing_token")) is not int
            or not has_exact_int_values(raw_report.get("resource_fencing_tokens"))
            or not isinstance(raw_report.get("dispatch_attempts"), list)
            or raw_report.get("promotable") is not False
        ):
            raise DispatchLedgerProtocolError()
        raw_attempts = raw_report["dispatch_attempts"]
        for raw_attempt in raw_attempts:
            if (
                not isinstance(raw_attempt, dict)
                or type(raw_attempt.get("claim_fencing_token")) is not int
                or not has_exact_int_values(raw_attempt.get("resource_fencing_tokens"))
            ):
                raise DispatchLedgerProtocolError()
            raw_receipt = raw_attempt.get("receipt")
            if raw_receipt is not None:
                if not isinstance(raw_receipt, dict):
                    raise DispatchLedgerProtocolError()
                raw_status = raw_receipt.get("http_status_code")
                raw_retry_after = raw_receipt.get("retry_after_seconds")
                if (
                    type(raw_status) is not int
                    or not 100 <= raw_status <= 599
                    or (
                        raw_retry_after is not None
                        and (type(raw_retry_after) is not int or not 0 <= raw_retry_after <= 86_400)
                    )
                ):
                    raise DispatchLedgerProtocolError()
        try:
            result = BudgetInterruptionReportResult.model_validate(payload)
        except Exception:
            raise DispatchLedgerProtocolError() from None

        report = result.report
        checkpoint_json = json.dumps(
            request_payload["checkpoint"],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        expected_checkpoint_sha256 = hashlib.sha256(checkpoint_json.encode("utf-8")).hexdigest()
        if (
            report.task_id != task_id
            or report.claim_fencing_token != request_payload["claim_fencing_token"]
            or report.resource_fencing_tokens != request_payload["resource_fencing_tokens"]
            or report.reason != request_payload["reason"]
            or report.summary != request_payload["summary"]
            or report.checkpoint != request_payload["checkpoint"]
            or report.checkpoint_sha256 != expected_checkpoint_sha256
            or report.checkpoint_integrity != "valid"
            or report.resource_fencing_tokens_integrity != "valid"
            or report.dispatch_attempt_ids != request_payload["dispatch_attempt_ids"]
            or report.dispatch_attempts_integrity != "valid"
            or len(report.dispatch_attempts) != len(request_payload["dispatch_attempt_ids"])
        ):
            raise DispatchLedgerProtocolError()

        for expected_id, attempt in zip(
            request_payload["dispatch_attempt_ids"], report.dispatch_attempts, strict=True
        ):
            receipt = attempt.receipt
            if (
                attempt.id != expected_id
                or attempt.task_id != task_id
                or attempt.claim_fencing_token != request_payload["claim_fencing_token"]
                or attempt.resource_fencing_tokens != request_payload["resource_fencing_tokens"]
                or attempt.status != "reported"
                or receipt is None
                or receipt.dispatch_attempt_id != expected_id
                or receipt.source != "client_reported"
            ):
                raise DispatchLedgerProtocolError()

        return result.model_dump(mode="json")

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
            error_code = _read_dispatch_api_error_code(exc)
            try:
                exc.close()
            except Exception:
                pass
            error = DispatchLedgerHttpError(exc.code, error_code)
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
                raise DispatchLedgerHttpError(status_code, _read_dispatch_api_error_code(response))
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
    retry_after_seconds: int | None = None
    provider_usage_report: Mapping[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class ProviderJsonHttpResponse:
    """Bounded decoded JSON response from a fixed-endpoint provider adapter.

    Only Retry-After and Content-Type response headers are retained. A decoded
    payload is available when body_status is "available", but omitted from repr
    and never copied into the dispatch receipt.
    """

    status_code: int
    headers: Mapping[str, str]
    payload: Any | None = field(repr=False)
    body_status: Literal["available", "invalid_json", "too_large", "unavailable"]

    def json(self) -> Any | None:
        """Return the decoded JSON payload, or None when it was unavailable."""

        return self.payload


@dataclass(frozen=True, slots=True)
class OpenAIResponsesHttpResponse(ProviderJsonHttpResponse):
    """OpenAI response type retained for source and introspection compatibility."""


@dataclass(frozen=True, slots=True)
class DispatchRetryPolicy:
    """Explicit finite retry policy for selected server failures.

    429 is deliberately never retried here: it can mean exhausted provider
    quota, and Retry-After may point beyond a quota reset. A retry is permitted
    only for 500/502/503/504 responses with a bounded Retry-After value.
    """

    max_attempts: int
    max_retry_after_seconds: int = 30
    max_total_wait_seconds: int = 60

    def __post_init__(self) -> None:
        if type(self.max_attempts) is not int or not 1 <= self.max_attempts <= 10:
            raise ValueError("max_attempts must be an integer between 1 and 10")
        if (
            type(self.max_retry_after_seconds) is not int
            or not 0 <= self.max_retry_after_seconds <= 86_400
        ):
            raise ValueError("max_retry_after_seconds must be an integer between 0 and 86400")
        if (
            type(self.max_total_wait_seconds) is not int
            or not 0 <= self.max_total_wait_seconds <= 86_400
        ):
            raise ValueError("max_total_wait_seconds must be an integer between 0 and 86400")


@dataclass(frozen=True, slots=True)
class DispatchRetryResult(Generic[ResponseT]):
    """Receipted attempts from one bounded retry sequence."""

    attempts: tuple[DispatchResult[ResponseT], ...]

    @property
    def response(self) -> ResponseT:
        return self.attempts[-1].response


class DispatchRetryStopped(RuntimeError, Generic[ResponseT]):
    """A retry sequence stopped; prior receipted attempts remain available."""

    def __init__(
        self,
        attempts: tuple[DispatchResult[ResponseT], ...],
        failure: Exception,
    ) -> None:
        self.attempts = attempts
        self.http_status_code = (
            failure.status_code if isinstance(failure, DispatchLedgerHttpError) else None
        )
        self.error_code = (
            failure.error_code if isinstance(failure, DispatchLedgerHttpError) else None
        )
        self.failure_type = _safe_failure_type(failure)
        self.current_attempt_id = getattr(failure, "dispatch_attempt_id", None)
        self.current_attempt_http_status_code = (
            failure.http_status_code if isinstance(failure, DispatchReceiptUnrecorded) else None
        )
        if isinstance(failure, DispatchLedgerError):
            budget_denied = (
                isinstance(failure, DispatchLedgerHttpError)
                and failure.status_code == 409
                and failure.error_code
                in {
                    "task_dispatch_budget_exhausted",
                    "descendant_dispatch_budget_exhausted",
                    "task_dispatch_outstanding_budget_exhausted",
                    "descendant_dispatch_outstanding_budget_exhausted",
                }
            )
            self.current_attempt_state = (
                "reservation_denied" if budget_denied else "reservation_outcome_unknown"
            )
            self.reservation_state = "denied" if budget_denied else "unknown"
            self.provider_send_state = "not_started"
        elif isinstance(failure, DispatchReservationReplay):
            self.current_attempt_state = "reservation_replayed"
            self.reservation_state = "existing"
            self.provider_send_state = "not_started"
        elif isinstance(failure, DispatchReservationInvalid):
            self.current_attempt_state = "reservation_outcome_unknown"
            self.reservation_state = "unknown"
            self.provider_send_state = "not_started"
        elif isinstance(failure, DispatchOutcomeUnknown):
            self.current_attempt_state = "outcome_unknown"
            self.reservation_state = "created"
            self.provider_send_state = "unknown"
        elif isinstance(failure, DispatchResponseInvalid):
            self.current_attempt_state = "response_unreceipted"
            self.reservation_state = "created"
            self.provider_send_state = "response_received"
        elif isinstance(failure, DispatchReceiptUnrecorded):
            self.current_attempt_state = "receipt_unconfirmed"
            self.reservation_state = "created"
            self.provider_send_state = "response_received"
        else:
            raise TypeError("failure must be a known dispatch interruption")
        super().__init__(
            "dispatch retry sequence stopped; prior receipted attempts remain available; "
            f"current attempt state: {self.current_attempt_state}"
        )


_RETRYABLE_SERVER_STATUS_CODES = frozenset({500, 502, 503, 504})
_RETRY_IDEMPOTENCY_KEY_MAX_LENGTH = 188


def dispatch_with_retries(
    *,
    ledger: DispatchLedger,
    task_id: str,
    claim_fencing_token: int,
    resource_fencing_tokens: Mapping[str, int],
    idempotency_key: str,
    provider_idempotency_key: str,
    send_once: Callable[[str], ResponseT],
    policy: DispatchRetryPolicy,
    wait: Callable[[float], None] = time.sleep,
    usage_report_from_response: Callable[[ResponseT], ClientReportedProviderUsage] | None = None,
) -> DispatchRetryResult[ResponseT]:
    """Run an explicit bounded retry sequence through durable dispatch slots.

    Each invocation gets a distinct ACP idempotency key and reservation; the
    same provider idempotency key is passed to every callback. The callback
    must submit that key to a provider that guarantees deduplication for this
    operation. This function cannot verify either condition. Only selected
    5xx responses with a Retry-After within both per-delay and total-wait caps
    are retried. A 429, missing/invalid/too-long hint, ambiguous send, failed
    receipt, or reservation denial ends the sequence. The caller's transport
    must still have its own retries and redirects disabled.
    """

    if not isinstance(policy, DispatchRetryPolicy):
        raise TypeError("policy must be a DispatchRetryPolicy")
    if not callable(wait):
        raise TypeError("wait must be callable")
    if (
        not isinstance(provider_idempotency_key, str)
        or not 1 <= len(provider_idempotency_key) <= 255
        or any(not 0x21 <= ord(char) <= 0x7E for char in provider_idempotency_key)
    ):
        raise ValueError("provider_idempotency_key must be 1..255 visible ASCII characters")
    if (
        not isinstance(idempotency_key, str)
        or not 1 <= len(idempotency_key) <= _RETRY_IDEMPOTENCY_KEY_MAX_LENGTH
        or any(
            char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-"
            for char in idempotency_key
        )
    ):
        raise ValueError("idempotency_key must be 1..188 visible token characters")

    attempts: list[DispatchResult[ResponseT]] = []
    total_wait_seconds = 0
    for attempt_number in range(1, policy.max_attempts + 1):
        try:
            result = dispatch_once(
                ledger=ledger,
                task_id=task_id,
                claim_fencing_token=claim_fencing_token,
                resource_fencing_tokens=resource_fencing_tokens,
                idempotency_key=f"{idempotency_key}:attempt:{attempt_number}",
                send_once=lambda: send_once(provider_idempotency_key),
                usage_report_from_response=usage_report_from_response,
            )
        except (
            DispatchLedgerError,
            DispatchReservationReplay,
            DispatchReservationInvalid,
            DispatchOutcomeUnknown,
            DispatchResponseInvalid,
            DispatchReceiptUnrecorded,
        ) as exc:
            if attempts:
                raise DispatchRetryStopped(tuple(attempts), exc) from None
            raise
        attempts.append(result)
        delay = result.retry_after_seconds
        if (
            attempt_number >= policy.max_attempts
            or result.response.status_code not in _RETRYABLE_SERVER_STATUS_CODES
            or delay is None
            or delay > policy.max_retry_after_seconds
            or total_wait_seconds + delay > policy.max_total_wait_seconds
        ):
            break
        wait(float(delay))
        total_wait_seconds += delay

    return DispatchRetryResult(attempts=tuple(attempts))


def dispatch_once(
    *,
    ledger: DispatchLedger,
    task_id: str,
    claim_fencing_token: int,
    resource_fencing_tokens: Mapping[str, int],
    idempotency_key: str,
    send_once: Callable[[], ResponseT],
    usage_report_from_response: Callable[[ResponseT], ClientReportedProviderUsage] | None = None,
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

    provider_usage_report: Mapping[str, Any] | None = None
    if usage_report_from_response is not None:
        try:
            observation = usage_report_from_response(response)
            if not isinstance(observation, ClientReportedProviderUsage):
                raise TypeError("usage extractor returned an unsupported result")
            provider_usage_report = ProviderUsageReport.model_validate(
                observation.as_dict()
            ).model_dump()
        except Exception:
            observation = _provider_usage_extraction_failed()
            provider_usage_report = ProviderUsageReport.model_validate(
                observation.as_dict()
            ).model_dump()

    try:
        receipt_arguments = {
            "task_id": task_id,
            "dispatch_attempt_id": reservation.dispatch_attempt_id,
            "claim_fencing_token": claim_fencing_token,
            "http_status_code": status_code,
            "retry_after_seconds": retry_after_seconds,
        }
        if provider_usage_report is None:
            ledger.record_dispatch_attempt_receipt(**receipt_arguments)
        else:
            ledger.record_dispatch_attempt_receipt(
                **receipt_arguments,
                provider_usage_report=provider_usage_report,
            )
    except Exception as exc:
        error = DispatchReceiptUnrecorded(
            reservation.dispatch_attempt_id, status_code, _safe_failure_type(exc)
        )
    else:
        error = None
    if error is not None:
        raise error

    return DispatchResult(
        dispatch_attempt_id=reservation.dispatch_attempt_id,
        response=response,
        retry_after_seconds=retry_after_seconds,
        provider_usage_report=provider_usage_report,
    )


def dispatch_openai_responses_once(
    *,
    ledger: DispatchLedger,
    task_id: str,
    claim_fencing_token: int,
    resource_fencing_tokens: Mapping[str, int],
    idempotency_key: str,
    api_key: str,
    request_payload: Mapping[str, Any],
    timeout_seconds: float = 60.0,
    opener: _ProviderHttpOpener | None = None,
) -> DispatchResult[OpenAIResponsesHttpResponse]:
    """Make one non-streaming OpenAI Responses HTTP call under a durable reservation.

    The default urllib opener refuses redirects and performs no application-level
    retries. This function does not attach a provider idempotency key, retry a
    failed call, enforce provider quota/spend, or intercept other provider calls.
    An injected opener is intended for tests and must preserve the no-retry,
    no-redirect behavior. Usage is attached as client-reported metadata only.
    """

    encoded_payload = _encode_provider_request_payload(
        request_payload, false_options=("stream", "background")
    )
    _validate_provider_api_key(api_key)
    _validate_provider_timeout(timeout_seconds)

    selected_opener = opener if opener is not None else build_opener(_NoRedirectHandler())
    if not callable(getattr(selected_opener, "open", None)):
        raise TypeError("opener must provide an open method")
    request = Request(
        _OPENAI_RESPONSES_URL,
        data=encoded_payload,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )

    def send_once() -> OpenAIResponsesHttpResponse:
        return _send_provider_json_request(
            selected_opener,
            request,
            float(timeout_seconds),
            maximum_bytes=_MAX_OPENAI_RESPONSES_BYTES,
            response_type=OpenAIResponsesHttpResponse,
        )

    return dispatch_once(
        ledger=ledger,
        task_id=task_id,
        claim_fencing_token=claim_fencing_token,
        resource_fencing_tokens=resource_fencing_tokens,
        idempotency_key=idempotency_key,
        send_once=send_once,
        usage_report_from_response=lambda response: parse_openai_responses_usage(response.payload),
    )


def dispatch_anthropic_messages_once(
    *,
    ledger: DispatchLedger,
    task_id: str,
    claim_fencing_token: int,
    resource_fencing_tokens: Mapping[str, int],
    idempotency_key: str,
    api_key: str,
    request_payload: Mapping[str, Any],
    anthropic_version: str = _ANTHROPIC_API_VERSION,
    timeout_seconds: float = 60.0,
    opener: _ProviderHttpOpener | None = None,
) -> DispatchResult[ProviderJsonHttpResponse]:
    """Make one non-streaming Anthropic Messages call under a durable reservation.

    The fixed transport does not retry or follow redirects. Provider usage is
    attached as client-reported metadata only; this does not enforce provider
    quota/spend or intercept other Anthropic traffic.
    """

    encoded_payload = _encode_provider_request_payload(request_payload, false_options=("stream",))
    _validate_provider_api_key(api_key)
    _validate_provider_timeout(timeout_seconds)
    if (
        not isinstance(anthropic_version, str)
        or not 1 <= len(anthropic_version) <= 64
        or any(not 0x21 <= ord(char) <= 0x7E for char in anthropic_version)
    ):
        raise ValueError("anthropic_version must contain 1..64 visible ASCII characters")

    selected_opener = opener if opener is not None else build_opener(_NoRedirectHandler())
    if not callable(getattr(selected_opener, "open", None)):
        raise TypeError("opener must provide an open method")
    request = Request(
        _ANTHROPIC_MESSAGES_URL,
        data=encoded_payload,
        headers={
            "X-Api-Key": api_key,
            "Anthropic-Version": anthropic_version,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )

    return dispatch_once(
        ledger=ledger,
        task_id=task_id,
        claim_fencing_token=claim_fencing_token,
        resource_fencing_tokens=resource_fencing_tokens,
        idempotency_key=idempotency_key,
        send_once=lambda: _send_provider_json_request(
            selected_opener,
            request,
            float(timeout_seconds),
            maximum_bytes=_MAX_PROVIDER_RESPONSE_BYTES,
        ),
        usage_report_from_response=lambda response: parse_anthropic_messages_usage(
            response.payload
        ),
    )


def dispatch_gemini_generate_content_once(
    *,
    ledger: DispatchLedger,
    task_id: str,
    claim_fencing_token: int,
    resource_fencing_tokens: Mapping[str, int],
    idempotency_key: str,
    api_key: str,
    model: str,
    request_payload: Mapping[str, Any],
    timeout_seconds: float = 60.0,
    opener: _ProviderHttpOpener | None = None,
) -> DispatchResult[ProviderJsonHttpResponse]:
    """Make one Gemini Developer API GenerateContent call under a reservation.

    This fixed transport is for the Google AI Developer API, not Vertex AI or
    Gemini Interactions. It does not retry or follow redirects, and its parsed
    usage remains client-reported rather than a quota/spend enforcement signal.
    """

    encoded_payload = _encode_provider_request_payload(
        request_payload, forbidden_options=("model", "stream")
    )
    _validate_provider_api_key(api_key)
    _validate_provider_timeout(timeout_seconds)
    if not _valid_gemini_model_name(model):
        raise ValueError("model must be a plain Gemini Developer API model name")

    selected_opener = opener if opener is not None else build_opener(_NoRedirectHandler())
    if not callable(getattr(selected_opener, "open", None)):
        raise TypeError("opener must provide an open method")
    request = Request(
        f"{_GEMINI_GENERATE_CONTENT_URL}{quote(model, safe='-._~')}:generateContent",
        data=encoded_payload,
        headers={
            "X-Goog-Api-Key": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )

    return dispatch_once(
        ledger=ledger,
        task_id=task_id,
        claim_fencing_token=claim_fencing_token,
        resource_fencing_tokens=resource_fencing_tokens,
        idempotency_key=idempotency_key,
        send_once=lambda: _send_provider_json_request(
            selected_opener,
            request,
            float(timeout_seconds),
            maximum_bytes=_MAX_PROVIDER_RESPONSE_BYTES,
        ),
        usage_report_from_response=lambda response: parse_gemini_generate_content_usage(
            response.payload
        ),
    )


def _read_openai_responses_response(
    status_code: int, headers: Any, response: _JsonResponse
) -> OpenAIResponsesHttpResponse:
    return _read_provider_json_response(
        status_code,
        headers,
        response,
        maximum_bytes=_MAX_OPENAI_RESPONSES_BYTES,
        response_type=OpenAIResponsesHttpResponse,
    )


def _send_provider_json_request(
    opener: _ProviderHttpOpener,
    request: Request,
    timeout_seconds: float,
    *,
    maximum_bytes: int,
    response_type: type[ProviderJsonHttpResponse] = ProviderJsonHttpResponse,
) -> ProviderJsonHttpResponse:
    try:
        response = opener.open(request, timeout=timeout_seconds)
    except HTTPError as exc:
        return _read_provider_json_response(
            exc.code,
            exc.headers,
            exc,
            maximum_bytes=maximum_bytes,
            response_type=response_type,
        )
    return _read_provider_json_response(
        response.status,
        response.headers,
        response,
        maximum_bytes=maximum_bytes,
        response_type=response_type,
    )


def _read_provider_json_response(
    status_code: int,
    headers: Any,
    response: _JsonResponse,
    *,
    maximum_bytes: int = _MAX_PROVIDER_RESPONSE_BYTES,
    response_type: type[ProviderJsonHttpResponse] = ProviderJsonHttpResponse,
) -> ProviderJsonHttpResponse:
    selected_headers = _safe_openai_response_headers(headers)
    try:
        body = response.read(maximum_bytes + 1)
    except Exception:
        return response_type(status_code, selected_headers, None, "unavailable")
    finally:
        _close_openai_response(response)

    if not isinstance(body, bytes):
        return response_type(status_code, selected_headers, None, "unavailable")
    if len(body) > maximum_bytes:
        return response_type(status_code, selected_headers, None, "too_large")
    try:
        payload = json.loads(body.decode("utf-8"))
    except (ValueError, RecursionError):
        return response_type(status_code, selected_headers, None, "invalid_json")
    return response_type(status_code, selected_headers, payload, "available")


def _encode_provider_request_payload(
    request_payload: Mapping[str, Any],
    *,
    false_options: tuple[str, ...] = (),
    forbidden_options: tuple[str, ...] = (),
) -> bytes:
    if not isinstance(request_payload, Mapping):
        raise TypeError("request_payload must be a mapping")
    payload = dict(request_payload)
    for request_option in false_options:
        value = payload.get(request_option, False)
        if type(value) is not bool or value:
            raise ValueError(
                f"{request_option} must be false for report-only single-response dispatch"
            )
    if any(request_option in payload for request_option in forbidden_options):
        raise ValueError("request_payload contains a field not accepted by this endpoint adapter")
    try:
        return json.dumps(
            payload, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        raise ValueError("request_payload must be JSON-serializable") from None


def _validate_provider_api_key(api_key: str) -> None:
    if (
        not isinstance(api_key, str)
        or not 1 <= len(api_key) <= 4096
        or any(not 0x21 <= ord(char) <= 0x7E for char in api_key)
    ):
        raise ValueError("api_key must contain 1..4096 visible ASCII characters")


def _validate_provider_timeout(timeout_seconds: float) -> None:
    if type(timeout_seconds) not in {int, float} or not 0 < timeout_seconds <= 300:
        raise ValueError("timeout_seconds must be greater than 0 and at most 300")


def _valid_gemini_model_name(model: object) -> bool:
    return (
        isinstance(model, str)
        and 1 <= len(model) <= 128
        and model.isascii()
        and model[0].isalnum()
        and all(char.isalnum() or char in "._-" for char in model)
    )


def _safe_openai_response_headers(headers: Any) -> dict[str, str]:
    safe: dict[str, str] = {}
    if headers is None:
        return safe
    try:
        items = headers.items()
        for name, value in items:
            if not isinstance(name, str) or not isinstance(value, str):
                continue
            canonical = {"retry-after": "Retry-After", "content-type": "Content-Type"}.get(
                name.casefold()
            )
            if (
                canonical is not None
                and len(value) <= 1024
                and "\r" not in value
                and "\n" not in value
            ):
                safe[canonical] = value
    except Exception:
        return {}
    return safe


def _close_openai_response(response: Any) -> None:
    try:
        response.close()
    except Exception:
        pass


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


def _read_dispatch_api_error_code(response: Any) -> str | None:
    """Read only a bounded, machine-readable API error code; discard its body."""

    try:
        body = response.read(_MAX_COORDINATION_ERROR_BYTES + 1)
    except Exception:
        return None
    if not isinstance(body, bytes) or len(body) > _MAX_COORDINATION_ERROR_BYTES:
        return None
    try:
        payload = json.loads(body)
    except (ValueError, RecursionError):
        return None
    if not isinstance(payload, Mapping):
        return None
    return _safe_api_error_code(payload.get("error"))


def _safe_api_error_code(value: object) -> str | None:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 64
        or value[0] not in "abcdefghijklmnopqrstuvwxyz"
        or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789_" for character in value)
    ):
        return None
    return value


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
    "OpenAIResponsesHttpResponse",
    "ProviderJsonHttpResponse",
    "DispatchReceiptUnrecorded",
    "DispatchResult",
    "DispatchRetryPolicy",
    "DispatchRetryResult",
    "DispatchRetryStopped",
    "dispatch_with_retries",
    "dispatch_anthropic_messages_once",
    "dispatch_gemini_generate_content_once",
    "dispatch_openai_responses_once",
    "dispatch_once",
]
