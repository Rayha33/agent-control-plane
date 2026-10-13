from __future__ import annotations

import io
import json
import sys
import traceback
from dataclasses import dataclass, replace
from datetime import datetime
from urllib.error import HTTPError
from urllib.request import Request

import pytest

import agent_control_plane.dispatch_client as dispatch_client_module
from agent_control_plane.dispatch_client import (
    CoordinationHttpDispatchLedger,
    DispatchLedgerHttpError,
    DispatchLedgerTransportError,
    DispatchOutcomeUnknown,
    DispatchReceiptUnrecorded,
    DispatchReservation,
    DispatchReservationReplay,
    DispatchResponseInvalid,
    DispatchRetryPolicy,
    dispatch_once,
    dispatch_openai_responses_once,
    dispatch_with_retries,
)
from agent_control_plane.provider_usage import parse_openai_responses_usage


@dataclass(frozen=True)
class FakeResponse:
    status_code: int
    retry_after_seconds: int | None = None


@dataclass(frozen=True)
class StandardHttpResponse:
    status_code: int
    headers: dict[str, str]
    body: dict[str, object] | None = None

    def json(self) -> dict[str, object] | None:
        return self.body


class FakeLedger:
    def __init__(self) -> None:
        self.reservations: dict[str, DispatchReservation] = {}
        self.reservation_keys: list[str] = []
        self.reserve_calls: list[tuple[str, int, dict[str, int], str]] = []
        self.receipts: list[tuple[str, int, int | None]] = []
        self.usage_reports: list[tuple[str, dict[str, object]]] = []
        self.lose_next_reservation_response = False
        self.reserve_error: Exception | None = None
        self.receipt_error: Exception | None = None
        self.reservation_limit: int | None = None

    def reserve_dispatch_attempt(
        self,
        *,
        task_id: str,
        claim_fencing_token: int,
        resource_fencing_tokens: dict[str, int],
        idempotency_key: str,
    ) -> DispatchReservation:
        self.reserve_calls.append(
            (task_id, claim_fencing_token, dict(resource_fencing_tokens), idempotency_key)
        )
        self.reservation_keys.append(idempotency_key)
        if self.reserve_error is not None:
            raise self.reserve_error
        existing = self.reservations.get(idempotency_key)
        if existing is not None:
            return DispatchReservation(existing.dispatch_attempt_id, created=False)
        if self.reservation_limit is not None and len(self.reservations) >= self.reservation_limit:
            raise RuntimeError("task_dispatch_budget_exhausted")
        reservation = DispatchReservation(
            dispatch_attempt_id=f"attempt-{len(self.reservations) + 1}", created=True
        )
        self.reservations[idempotency_key] = reservation
        if self.lose_next_reservation_response:
            self.lose_next_reservation_response = False
            raise TimeoutError("reservation response lost after durable commit")
        return reservation

    def record_dispatch_attempt_receipt(
        self,
        *,
        task_id: str,
        dispatch_attempt_id: str,
        claim_fencing_token: int,
        http_status_code: int,
        retry_after_seconds: int | None,
        provider_usage_report: dict[str, object] | None = None,
    ) -> None:
        del task_id, claim_fencing_token
        if self.receipt_error is not None:
            raise self.receipt_error
        self.receipts.append((dispatch_attempt_id, http_status_code, retry_after_seconds))
        if provider_usage_report is not None:
            self.usage_reports.append((dispatch_attempt_id, provider_usage_report))


class FakeApiResponse:
    def __init__(self, status: int, payload: object) -> None:
        self.status = status
        self.body = json.dumps(payload).encode("utf-8")

    def read(self, amount: int = -1) -> bytes:
        return self.body if amount < 0 else self.body[:amount]

    def close(self) -> None:
        pass


class FakeApiOpener:
    def __init__(self, *responses_or_errors: object) -> None:
        self.responses_or_errors = list(responses_or_errors)
        self.requests: list[tuple[Request, float]] = []

    def open(self, request: Request, timeout: float) -> FakeApiResponse:
        self.requests.append((request, timeout))
        outcome = self.responses_or_errors.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class FakeProviderResponse:
    def __init__(self, status: int, headers: dict[str, str], body: bytes) -> None:
        self.status = status
        self.headers = headers
        self.body = body
        self.read_limits: list[int] = []
        self.closed = False

    def read(self, amount: int = -1) -> bytes:
        self.read_limits.append(amount)
        return self.body if amount < 0 else self.body[:amount]

    def close(self) -> None:
        self.closed = True


class FakeProviderOpener:
    def __init__(self, *responses_or_errors: object) -> None:
        self.responses_or_errors = list(responses_or_errors)
        self.requests: list[tuple[Request, float]] = []

    def open(self, request: Request, timeout: float) -> FakeProviderResponse:
        self.requests.append((request, timeout))
        outcome = self.responses_or_errors.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class ClientTestOpener:
    def __init__(self, client) -> None:
        self.client = client
        self.payloads: list[dict[str, object]] = []

    def open(self, request: Request, timeout: float) -> FakeApiResponse:
        assert timeout > 0
        response = self.client.request(
            request.get_method(),
            request.full_url,
            headers=dict(request.header_items()),
            content=request.data,
            follow_redirects=False,
        )
        payload = response.json()
        self.payloads.append(payload)
        return FakeApiResponse(response.status_code, payload)


def _dispatch(ledger: FakeLedger, idempotency_key: str, send_once):
    return dispatch_once(
        ledger=ledger,
        task_id="task-1",
        claim_fencing_token=7,
        resource_fencing_tokens={"repo:file:src/app.py": 11},
        idempotency_key=idempotency_key,
        send_once=send_once,
    )


def _dispatch_retries(
    ledger: FakeLedger,
    idempotency_key: str,
    send_once,
    policy,
    wait,
    usage_report_from_response=None,
):
    return dispatch_with_retries(
        ledger=ledger,
        task_id="task-1",
        claim_fencing_token=7,
        resource_fencing_tokens={"repo:file:src/app.py": 11},
        idempotency_key=idempotency_key,
        provider_idempotency_key="provider-operation-key",
        send_once=send_once,
        policy=policy,
        wait=wait,
        usage_report_from_response=usage_report_from_response,
    )


def _dispatch_openai(ledger: FakeLedger, opener=None, *, request_payload=None):
    return dispatch_openai_responses_once(
        ledger=ledger,
        task_id="task-1",
        claim_fencing_token=7,
        resource_fencing_tokens={"repo:file:src/app.py": 11},
        idempotency_key="openai-responses-once",
        api_key="sk-test-not-a-real-key",
        request_payload=request_payload or {"model": "gpt-5.6", "input": "hello"},
        opener=opener,
    )


def test_openai_responses_adapter_sends_once_and_records_report_only_usage() -> None:
    ledger = FakeLedger()
    body = {
        "object": "response",
        "id": "resp_123456",
        "model": "gpt-5.6",
        "status": "completed",
        "created_at": 1_791_883_739,
        "output": [{"type": "output_text", "text": "response-body-secret-marker"}],
        "usage": {"input_tokens": 4, "output_tokens": 3, "total_tokens": 7},
    }
    raw = FakeProviderResponse(200, {"content-type": "application/json"}, json.dumps(body).encode())
    opener = FakeProviderOpener(raw)

    result = _dispatch_openai(ledger, opener)

    assert len(opener.requests) == 1
    request, timeout = opener.requests[0]
    assert request.full_url == "https://api.openai.com/v1/responses"
    assert request.get_method() == "POST"
    headers = {name.casefold(): value for name, value in request.header_items()}
    assert headers["authorization"] == "Bearer sk-test-not-a-real-key"
    assert headers["content-type"] == "application/json"
    assert "idempotency-key" not in headers
    assert json.loads(request.data) == {"model": "gpt-5.6", "input": "hello"}
    assert timeout == 60.0
    assert raw.closed is True
    assert result.response.payload == body
    assert result.response.body_status == "available"
    assert result.provider_usage_report["status"] == "reported"
    assert result.provider_usage_report["measurements"] == {
        "input_tokens": 4,
        "output_tokens": 3,
        "total_tokens": 7,
    }
    assert ledger.receipts == [("attempt-1", 200, None)]
    assert ledger.usage_reports == [("attempt-1", result.provider_usage_report)]
    assert "sk-test-not-a-real-key" not in str(ledger.usage_reports)
    assert "response-body-secret-marker" not in str(ledger.usage_reports)
    assert "sk-test-not-a-real-key" not in repr(result)
    assert "response-body-secret-marker" not in repr(result)


@pytest.mark.parametrize(
    "request_payload",
    [
        {"model": "gpt-5.6", "input": "hello", "stream": True},
        {"model": "gpt-5.6", "input": "hello", "background": True},
        {"model": "gpt-5.6", "input": "hello", "stream": 1},
    ],
)
def test_openai_responses_adapter_rejects_streaming_before_reservation(request_payload) -> None:
    ledger = FakeLedger()
    opener = FakeProviderOpener()

    with pytest.raises(ValueError):
        _dispatch_openai(ledger, opener, request_payload=request_payload)

    assert ledger.reserve_calls == []
    assert opener.requests == []


def test_openai_responses_adapter_rejects_header_injection_before_reservation() -> None:
    ledger = FakeLedger()
    opener = FakeProviderOpener()

    with pytest.raises(ValueError, match="visible ASCII"):
        dispatch_openai_responses_once(
            ledger=ledger,
            task_id="task-1",
            claim_fencing_token=7,
            resource_fencing_tokens={},
            idempotency_key="openai-header-injection",
            api_key="key\r\nX-Leak: yes",
            request_payload={"model": "gpt-5.6", "input": "hello"},
            opener=opener,
        )

    assert ledger.reserve_calls == []
    assert opener.requests == []


def test_openai_responses_adapter_refuses_redirect_and_never_resends(monkeypatch) -> None:
    ledger = FakeLedger()
    redirect = HTTPError(
        "https://api.openai.com/v1/responses",
        302,
        "Found",
        {"Location": "https://attacker.invalid/capture"},
        io.BytesIO(b'{"error":"redirect refused"}'),
    )
    opener = FakeProviderOpener(redirect)
    registered_handlers = []

    def build_fake_opener(*handlers):
        registered_handlers.extend(handlers)
        return opener

    monkeypatch.setattr(dispatch_client_module, "build_opener", build_fake_opener)

    result = _dispatch_openai(ledger)

    assert len(registered_handlers) == 1
    handler = registered_handlers[0]
    assert (
        handler.redirect_request(
            Request("https://api.openai.com/v1/responses"),
            None,
            302,
            "Found",
            {"Location": "https://attacker.invalid/capture"},
            "https://attacker.invalid/capture",
        )
        is None
    )
    assert len(opener.requests) == 1
    assert result.response.status_code == 302
    assert result.retry_after_seconds is None
    assert ledger.receipts == [("attempt-1", 302, None)]
    assert "redirect refused" not in str(ledger.usage_reports)


def test_openai_responses_adapter_records_429_without_retry() -> None:
    ledger = FakeLedger()
    too_many_requests = HTTPError(
        "https://api.openai.com/v1/responses",
        429,
        "Too Many Requests",
        {"Retry-After": "900"},
        io.BytesIO(b'{"error":{"type":"rate_limit"}}'),
    )
    opener = FakeProviderOpener(too_many_requests)

    result = _dispatch_openai(ledger, opener)

    assert len(opener.requests) == 1
    assert result.response.status_code == 429
    assert result.retry_after_seconds == 900
    assert result.provider_usage_report["status"] == "missing"
    assert ledger.receipts == [("attempt-1", 429, 900)]


def test_openai_responses_adapter_does_not_resend_an_ambiguous_send() -> None:
    ledger = FakeLedger()
    opener = FakeProviderOpener(TimeoutError("provider outcome unavailable"))

    with pytest.raises(DispatchOutcomeUnknown) as raised:
        _dispatch_openai(ledger, opener)

    assert len(opener.requests) == 1
    assert len(ledger.reserve_calls) == 1
    assert ledger.receipts == []
    assert "sk-test-not-a-real-key" not in str(raised.value)
    assert "provider outcome unavailable" not in str(raised.value)


def test_openai_responses_adapter_records_receipt_when_body_is_not_json() -> None:
    ledger = FakeLedger()
    raw = FakeProviderResponse(200, {}, b"not-json")
    opener = FakeProviderOpener(raw)

    result = _dispatch_openai(ledger, opener)

    assert result.response.status_code == 200
    assert result.response.body_status == "invalid_json"
    assert result.response.payload is None
    assert result.provider_usage_report["status"] == "missing"
    assert ledger.receipts == [("attempt-1", 200, None)]


def test_openai_responses_adapter_records_receipt_for_deeply_nested_json() -> None:
    ledger = FakeLedger()
    raw = FakeProviderResponse(200, {}, b"[" * 10_000 + b"0" + b"]" * 10_000)
    opener = FakeProviderOpener(raw)

    result = _dispatch_openai(ledger, opener)

    assert result.response.status_code == 200
    assert result.response.body_status == "invalid_json"
    assert result.response.payload is None
    assert result.provider_usage_report["status"] == "missing"
    assert ledger.receipts == [("attempt-1", 200, None)]


def test_openai_responses_adapter_records_receipt_for_integer_digit_limit() -> None:
    original_limit = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(640)
    ledger = FakeLedger()
    raw = FakeProviderResponse(200, {}, b'{"n":' + b"9" * 700 + b"}")
    opener = FakeProviderOpener(raw)
    try:
        result = _dispatch_openai(ledger, opener)
    finally:
        sys.set_int_max_str_digits(original_limit)

    assert result.response.status_code == 200
    assert result.response.body_status == "invalid_json"
    assert result.response.payload is None
    assert result.provider_usage_report["status"] == "missing"
    assert ledger.receipts == [("attempt-1", 200, None)]


def test_openai_responses_adapter_bounds_and_reports_unavailable_json(monkeypatch) -> None:
    monkeypatch.setattr(dispatch_client_module, "_MAX_OPENAI_RESPONSES_BYTES", 4)
    ledger = FakeLedger()
    raw = FakeProviderResponse(200, {}, b"12345")
    opener = FakeProviderOpener(raw)

    result = _dispatch_openai(ledger, opener)

    assert raw.read_limits == [5]
    assert result.response.body_status == "too_large"
    assert result.response.payload is None
    assert result.provider_usage_report["status"] == "missing"
    assert ledger.receipts == [("attempt-1", 200, None)]


def test_reservation_denial_and_stale_fence_never_invoke_transport() -> None:
    for reason in ("task_dispatch_budget_exhausted", "claim_fencing_token_stale"):
        ledger = FakeLedger()
        ledger.reserve_error = RuntimeError(reason)
        sends: list[None] = []

        def send_once(sends=sends) -> FakeResponse:
            sends.append(None)
            return FakeResponse(200)

        with pytest.raises(RuntimeError, match=reason):
            _dispatch(ledger, "denied", send_once)

        assert sends == []
        assert ledger.receipts == []


def test_dispatch_without_usage_preserves_legacy_ledger_receipt_signature() -> None:
    class LegacyReceiptLedger:
        def __init__(self) -> None:
            self.inner = FakeLedger()

        def reserve_dispatch_attempt(self, **kwargs) -> DispatchReservation:
            return self.inner.reserve_dispatch_attempt(**kwargs)

        def record_dispatch_attempt_receipt(
            self,
            *,
            task_id: str,
            dispatch_attempt_id: str,
            claim_fencing_token: int,
            http_status_code: int,
            retry_after_seconds: int | None,
        ) -> None:
            self.inner.record_dispatch_attempt_receipt(
                task_id=task_id,
                dispatch_attempt_id=dispatch_attempt_id,
                claim_fencing_token=claim_fencing_token,
                http_status_code=http_status_code,
                retry_after_seconds=retry_after_seconds,
            )

    ledger = LegacyReceiptLedger()
    result = dispatch_once(
        ledger=ledger,
        task_id="task-1",
        claim_fencing_token=7,
        resource_fencing_tokens={},
        idempotency_key="legacy-ledger-receipt",
        send_once=lambda: FakeResponse(200),
    )

    assert result.response.status_code == 200
    assert ledger.inner.receipts == [("attempt-1", 200, None)]


def test_idempotent_reservation_replay_refuses_to_send() -> None:
    ledger = FakeLedger()
    sends: list[None] = []
    first = _dispatch(ledger, "same-key", lambda: (sends.append(None), FakeResponse(200))[1])

    with pytest.raises(DispatchReservationReplay) as replay:
        _dispatch(ledger, "same-key", lambda: sends.append(None))

    assert first.dispatch_attempt_id == "attempt-1"
    assert replay.value.dispatch_attempt_id == first.dispatch_attempt_id
    assert sends == [None]
    assert len(ledger.receipts) == 1


def test_429_is_recorded_once_without_automatic_retry() -> None:
    ledger = FakeLedger()
    sends: list[FakeResponse] = []

    def send_once() -> FakeResponse:
        response = FakeResponse(429, retry_after_seconds=30)
        sends.append(response)
        return response

    result = _dispatch(ledger, "429-key", send_once)

    assert result.response is sends[0]
    assert sends == [FakeResponse(429, retry_after_seconds=30)]
    assert ledger.reserve_calls == [("task-1", 7, {"repo:file:src/app.py": 11}, "429-key")]
    assert ledger.receipts == [("attempt-1", 429, 30)]


def test_explicit_retry_policy_reserves_each_bounded_503_attempt() -> None:
    ledger = FakeLedger()
    responses = [FakeResponse(503, retry_after_seconds=2), FakeResponse(200)]
    sends: list[int] = []
    waits: list[float] = []

    provider_keys: list[str] = []

    def send_once(provider_idempotency_key: str) -> FakeResponse:
        provider_keys.append(provider_idempotency_key)
        sends.append(len(sends) + 1)
        return responses.pop(0)

    result = _dispatch_retries(
        ledger,
        "bounded-retry",
        send_once,
        DispatchRetryPolicy(max_attempts=3, max_retry_after_seconds=5),
        waits.append,
    )

    assert result.response.status_code == 200
    assert [item.response.status_code for item in result.attempts] == [503, 200]
    assert [item.retry_after_seconds for item in result.attempts] == [2, None]
    assert sends == [1, 2]
    assert provider_keys == ["provider-operation-key", "provider-operation-key"]
    assert waits == [2.0]
    assert ledger.reservation_keys == [
        "bounded-retry:attempt:1",
        "bounded-retry:attempt:2",
    ]
    assert ledger.receipts == [("attempt-1", 503, 2), ("attempt-2", 200, None)]


def test_explicit_retry_policy_never_retries_429_even_with_retry_after() -> None:
    ledger = FakeLedger()
    responses = [
        StandardHttpResponse(
            429,
            {"Retry-After": "1"},
            {"error": {"type": "rate_limit_error"}},
        )
    ]
    sends: list[StandardHttpResponse] = []
    waits: list[float] = []

    def send_once(_provider_idempotency_key: str) -> StandardHttpResponse:
        response = responses.pop(0)
        sends.append(response)
        return response

    result = _dispatch_retries(
        ledger,
        "quota-response",
        send_once,
        DispatchRetryPolicy(max_attempts=4, max_retry_after_seconds=5),
        waits.append,
        usage_report_from_response=lambda response: parse_openai_responses_usage(response.json()),
    )

    assert result.response.status_code == 429
    assert len(result.attempts) == 1
    assert len(sends) == 1
    assert waits == []
    assert len(ledger.reservation_keys) == 1
    assert ledger.receipts == [("attempt-1", 429, 1)]
    assert ledger.usage_reports[0][1]["status"] == "missing"


def test_explicit_retry_policy_does_not_retry_ambiguous_send() -> None:
    ledger = FakeLedger()
    sends: list[str] = []

    def send_once(provider_idempotency_key: str) -> FakeResponse:
        sends.append(provider_idempotency_key)
        raise TimeoutError("upstream outcome unknown")

    with pytest.raises(DispatchOutcomeUnknown):
        _dispatch_retries(
            ledger,
            "ambiguous-send",
            send_once,
            DispatchRetryPolicy(max_attempts=3),
            lambda _delay: None,
        )

    assert sends == ["provider-operation-key"]
    assert ledger.reservation_keys == ["ambiguous-send:attempt:1"]
    assert ledger.receipts == []


@pytest.mark.parametrize(
    "response, policy",
    [
        (FakeResponse(503), DispatchRetryPolicy(max_attempts=3)),
        (
            FakeResponse(503, retry_after_seconds=6),
            DispatchRetryPolicy(max_attempts=3, max_retry_after_seconds=5),
        ),
        (FakeResponse(501, retry_after_seconds=1), DispatchRetryPolicy(max_attempts=3)),
    ],
)
def test_explicit_retry_policy_stops_without_an_approved_retry_hint(response, policy) -> None:
    ledger = FakeLedger()
    sends: list[None] = []
    waits: list[float] = []

    result = _dispatch_retries(
        ledger,
        "retry-stops",
        lambda _provider_idempotency_key: (sends.append(None), response)[1],
        policy,
        waits.append,
    )

    assert result.response is response
    assert len(result.attempts) == 1
    assert sends == [None]
    assert waits == []
    assert len(ledger.receipts) == 1


def test_explicit_retry_policy_surfaces_dispatch_cap_before_second_send() -> None:
    ledger = FakeLedger()
    ledger.reservation_limit = 1
    responses = [FakeResponse(503, retry_after_seconds=0)]
    sends: list[None] = []

    with pytest.raises(RuntimeError, match="task_dispatch_budget_exhausted"):
        _dispatch_retries(
            ledger,
            "retry-cap",
            lambda _provider_idempotency_key: (sends.append(None), responses.pop(0))[1],
            DispatchRetryPolicy(max_attempts=3, max_retry_after_seconds=1),
            lambda _delay: None,
        )

    assert sends == [None]
    assert ledger.reservation_keys == ["retry-cap:attempt:1", "retry-cap:attempt:2"]
    assert ledger.receipts == [("attempt-1", 503, 0)]


def test_interrupted_retry_sequence_replays_first_key_and_does_not_resume() -> None:
    ledger = FakeLedger()
    responses = [FakeResponse(503, retry_after_seconds=1)]
    sends: list[None] = []
    policy = DispatchRetryPolicy(max_attempts=3, max_retry_after_seconds=2)

    with pytest.raises(InterruptedError):
        _dispatch_retries(
            ledger,
            "interrupted-sequence",
            lambda _provider_idempotency_key: (sends.append(None), responses.pop(0))[1],
            policy,
            lambda _delay: (_ for _ in ()).throw(InterruptedError()),
        )

    with pytest.raises(DispatchReservationReplay):
        _dispatch_retries(
            ledger,
            "interrupted-sequence",
            lambda _provider_idempotency_key: sends.append(None),
            policy,
            lambda _delay: None,
        )

    assert sends == [None]
    assert ledger.reservation_keys == [
        "interrupted-sequence:attempt:1",
        "interrupted-sequence:attempt:1",
    ]
    assert ledger.receipts == [("attempt-1", 503, 1)]


def test_explicit_retry_policy_caps_total_wait_across_the_sequence() -> None:
    ledger = FakeLedger()
    responses = [
        FakeResponse(503, retry_after_seconds=3),
        FakeResponse(503, retry_after_seconds=3),
        FakeResponse(200),
    ]
    sends: list[None] = []
    waits: list[float] = []

    result = _dispatch_retries(
        ledger,
        "total-wait-cap",
        lambda _provider_idempotency_key: (sends.append(None), responses.pop(0))[1],
        DispatchRetryPolicy(
            max_attempts=4,
            max_retry_after_seconds=10,
            max_total_wait_seconds=5,
        ),
        waits.append,
    )

    assert result.response.status_code == 503
    assert len(result.attempts) == 2
    assert sends == [None, None]
    assert waits == [3.0]
    assert ledger.receipts == [("attempt-1", 503, 3), ("attempt-2", 503, 3)]


@pytest.mark.parametrize("max_attempts", [True, 0, 11, 1.5])
def test_dispatch_retry_policy_rejects_unbounded_or_non_integer_attempts(max_attempts) -> None:
    with pytest.raises(ValueError, match="max_attempts"):
        DispatchRetryPolicy(max_attempts=max_attempts)


@pytest.mark.parametrize("max_total_wait_seconds", [True, -1, 86_401])
def test_dispatch_retry_policy_rejects_invalid_total_wait_caps(max_total_wait_seconds) -> None:
    with pytest.raises(ValueError, match="max_total_wait_seconds"):
        DispatchRetryPolicy(max_attempts=2, max_total_wait_seconds=max_total_wait_seconds)


def test_dispatch_with_retries_rejects_missing_provider_idempotency_before_reserving() -> None:
    ledger = FakeLedger()

    with pytest.raises(ValueError, match="provider_idempotency_key"):
        dispatch_with_retries(
            ledger=ledger,
            task_id="task-1",
            claim_fencing_token=7,
            resource_fencing_tokens={"repo:file:src/app.py": 11},
            idempotency_key="provider-key-required",
            provider_idempotency_key="\n",
            send_once=lambda _provider_key: FakeResponse(200),
            policy=DispatchRetryPolicy(max_attempts=2),
            wait=lambda _delay: None,
        )

    assert ledger.reserve_calls == []


def test_standard_http_response_retry_after_header_is_normalized() -> None:
    ledger = FakeLedger()
    result = _dispatch(
        ledger,
        "standard-http-response",
        lambda: StandardHttpResponse(429, {"Retry-After": "30"}),
    )

    assert result.response.status_code == 429
    assert ledger.receipts == [("attempt-1", 429, 30)]


def test_usage_extractor_failure_does_not_discard_the_http_receipt() -> None:
    ledger = FakeLedger()

    def fail_extraction(_response: FakeResponse):
        raise ValueError("sensitive provider response body")

    result = dispatch_once(
        ledger=ledger,
        task_id="task-1",
        claim_fencing_token=7,
        resource_fencing_tokens={},
        idempotency_key="usage-extractor-failure",
        send_once=lambda: FakeResponse(200),
        usage_report_from_response=fail_extraction,
    )

    assert result.response.status_code == 200
    assert ledger.receipts == [("attempt-1", 200, None)]
    assert ledger.usage_reports == [
        (
            "attempt-1",
            {
                "status": "invalid",
                "provider": "unknown",
                "adapter": "unknown",
                "source": "client_reported",
                "scope": "single_response",
                "unit": None,
                "observed_at": result.provider_usage_report["observed_at"],
                "response_id": None,
                "model": None,
                "response_created_at": None,
                "measurements": {},
                "freshness": "unknown",
                "enforcement": "report_only",
                "reason": "provider_usage_extractor_failed",
            },
        )
    ]
    assert "sensitive" not in str(ledger.usage_reports)


def test_malformed_usage_report_falls_back_without_losing_http_receipt() -> None:
    ledger = FakeLedger()

    def inconsistent_extraction(_response: FakeResponse):
        good_report = parse_openai_responses_usage(
            {
                "object": "response",
                "id": "resp_bad_total",
                "model": "gpt-5.6",
                "status": "completed",
                "usage": {"input_tokens": 2, "output_tokens": 3, "total_tokens": 5},
            }
        )
        return replace(
            good_report,
            measurements=(
                ("input_tokens", 2),
                ("output_tokens", 3),
                ("total_tokens", 99),
            ),
        )

    result = dispatch_once(
        ledger=ledger,
        task_id="task-1",
        claim_fencing_token=7,
        resource_fencing_tokens={},
        idempotency_key="malformed-usage-report",
        send_once=lambda: FakeResponse(200),
        usage_report_from_response=inconsistent_extraction,
    )

    assert result.response.status_code == 200
    assert ledger.receipts == [("attempt-1", 200, None)]
    assert ledger.usage_reports[0][1]["status"] == "invalid"
    assert ledger.usage_reports[0][1]["reason"] == "provider_usage_extractor_failed"
    assert ledger.usage_reports[0][1]["measurements"] == {}


def test_standard_http_response_http_date_retry_after_is_normalized() -> None:
    ledger = FakeLedger()
    _dispatch(
        ledger,
        "standard-http-date",
        lambda: StandardHttpResponse(503, {"retry-after": "Wed, 21 Oct 2015 07:28:00 GMT"}),
    )

    assert ledger.receipts == [("attempt-1", 503, 0)]


def test_retry_after_header_lookup_is_case_insensitive() -> None:
    ledger = FakeLedger()
    _dispatch(
        ledger,
        "uppercase-retry-after",
        lambda: StandardHttpResponse(429, {"RETRY-AFTER": "45"}),
    )

    assert ledger.receipts == [("attempt-1", 429, 45)]


def test_unrepresentable_retry_after_preserves_status_receipt_without_retry() -> None:
    ledger = FakeLedger()
    sends: list[FakeResponse] = []

    def send_once() -> FakeResponse:
        response = FakeResponse(429, retry_after_seconds=86_401)
        sends.append(response)
        return response

    result = _dispatch(ledger, "unrepresentable-retry-after", send_once)
    with pytest.raises(DispatchReservationReplay):
        _dispatch(ledger, "unrepresentable-retry-after", send_once)

    assert result.response.status_code == 429
    assert sends == [FakeResponse(429, retry_after_seconds=86_401)]
    assert ledger.receipts == [("attempt-1", 429, None)]


def test_missing_response_metadata_is_not_recorded_or_resent() -> None:
    ledger = FakeLedger()
    sends: list[object] = []

    def send_once() -> object:
        response = object()
        sends.append(response)
        return response

    with pytest.raises(DispatchResponseInvalid):
        _dispatch(ledger, "missing-response-metadata", send_once)
    with pytest.raises(DispatchReservationReplay):
        _dispatch(ledger, "missing-response-metadata", send_once)

    assert len(sends) == 1
    assert ledger.receipts == []


def test_explicit_retry_uses_a_fresh_reservation_and_one_send_each() -> None:
    ledger = FakeLedger()
    sends: list[int] = []

    first = _dispatch(ledger, "explicit-try-1", lambda: (sends.append(1), FakeResponse(429, 1))[1])
    second = _dispatch(ledger, "explicit-try-2", lambda: (sends.append(2), FakeResponse(200))[1])

    assert first.dispatch_attempt_id == "attempt-1"
    assert second.dispatch_attempt_id == "attempt-2"
    assert ledger.reservation_keys == ["explicit-try-1", "explicit-try-2"]
    assert sends == [1, 2]
    assert len(ledger.receipts) == 2


def test_lost_reservation_response_replay_does_not_send() -> None:
    ledger = FakeLedger()
    ledger.lose_next_reservation_response = True
    sends: list[None] = []
    with pytest.raises(TimeoutError, match="response lost"):
        _dispatch(ledger, "lost-reservation", lambda: sends.append(None))

    with pytest.raises(DispatchReservationReplay):
        _dispatch(ledger, "lost-reservation", lambda: sends.append(None))

    assert sends == []
    assert ledger.receipts == []


def test_ambiguous_send_consumes_reservation_and_same_key_is_not_resent() -> None:
    ledger = FakeLedger()
    sends: list[None] = []

    def ambiguous_send() -> FakeResponse:
        sends.append(None)
        raise TimeoutError("connection closed after write")

    with pytest.raises(DispatchOutcomeUnknown) as outcome:
        _dispatch(ledger, "ambiguous-send", ambiguous_send)
    with pytest.raises(DispatchReservationReplay):
        _dispatch(ledger, "ambiguous-send", ambiguous_send)

    assert outcome.value.dispatch_attempt_id == "attempt-1"
    assert sends == [None]
    assert ledger.receipts == []


def test_receipt_failure_does_not_repeat_provider_request() -> None:
    ledger = FakeLedger()
    ledger.receipt_error = TimeoutError("receipt response lost")
    sends: list[None] = []

    def send_once() -> FakeResponse:
        sends.append(None)
        return FakeResponse(200)

    with pytest.raises(DispatchReceiptUnrecorded) as failure:
        _dispatch(ledger, "receipt-loss", send_once)
    with pytest.raises(DispatchReservationReplay):
        _dispatch(ledger, "receipt-loss", send_once)

    assert failure.value.http_status_code == 200
    assert failure.value.failure_type == "TimeoutError"
    assert "receipt response lost" not in "".join(traceback.format_exception(failure.value))
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    assert sends == [None]
    assert ledger.receipts == []


def test_coordination_http_adapter_maps_real_routes_payloads_and_auth() -> None:
    opener = FakeApiOpener(
        FakeApiResponse(
            201,
            {"reservation": {"id": "attempt/one"}, "created": True},
        ),
        FakeApiResponse(
            200,
            {"receipt": {"dispatch_attempt_id": "attempt/one"}, "created": True},
        ),
    )
    ledger = CoordinationHttpDispatchLedger(
        base_url="https://coord.example/base/",
        bearer_token="test-bearer-secret",
        timeout_seconds=3,
        opener=opener,
    )

    reservation = ledger.reserve_dispatch_attempt(
        task_id="task/one",
        claim_fencing_token=7,
        resource_fencing_tokens={"repo:file:src/app.py": 11},
        idempotency_key="call-1",
    )
    ledger.record_dispatch_attempt_receipt(
        task_id="task/one",
        dispatch_attempt_id=reservation.dispatch_attempt_id,
        claim_fencing_token=7,
        http_status_code=429,
        retry_after_seconds=30,
    )

    reserve_request, reserve_timeout = opener.requests[0]
    receipt_request, receipt_timeout = opener.requests[1]
    assert reserve_request.full_url == (
        "https://coord.example/base/v1/tasks/task%2Fone/dispatch-attempts"
    )
    assert receipt_request.full_url == (
        "https://coord.example/base/v1/tasks/task%2Fone/dispatch-attempts/attempt%2Fone/receipt"
    )
    assert reserve_request.get_method() == receipt_request.get_method() == "POST"
    assert reserve_request.get_header("Authorization") == "Bearer test-bearer-secret"
    assert receipt_request.get_header("Authorization") == "Bearer test-bearer-secret"
    assert "test-bearer-secret" not in reserve_request.full_url
    assert json.loads(reserve_request.data) == {
        "claim_fencing_token": 7,
        "resource_fencing_tokens": {"repo:file:src/app.py": 11},
        "idempotency_key": "call-1",
    }
    assert json.loads(receipt_request.data) == {
        "claim_fencing_token": 7,
        "http_status_code": 429,
        "retry_after_seconds": 30,
    }
    assert reservation.dispatch_attempt_id == "attempt/one"
    assert reservation.created is True
    assert reserve_timeout == receipt_timeout == 3


def test_http_adapter_and_dispatch_once_integrate_with_reference_api(client, admin_headers) -> None:
    agent_response = client.post(
        "/v1/agents",
        headers=admin_headers,
        json={"name": "dispatch-client-integration", "owner": "tests", "role": "worker"},
    )
    assert agent_response.status_code == 201
    agent_id = agent_response.json()["id"]
    mandate_response = client.post(
        "/v1/mandates",
        headers=admin_headers,
        json={
            "agent_id": agent_id,
            "subject": f"agent:{agent_id}",
            "scopes": [{"action": "coordination.*", "resource": "task:*"}],
            "ttl_seconds": 3600,
        },
    )
    assert mandate_response.status_code == 201
    token = mandate_response.json()["token"]
    task_response = client.post(
        "/v1/tasks",
        headers=admin_headers,
        json={
            "title": "Exercise the dispatch HTTP adapter",
            "description": "Reserve and receipt through the published client adapter.",
            "acceptance_criteria": ["one reservation and one receipt"],
            "resources": ["repo:file:src/adapter_integration.py"],
            "priority": 80,
            "max_dispatch_attempts": 1,
        },
    )
    assert task_response.status_code == 201
    task = task_response.json()
    claim_response = client.post(
        f"/v1/tasks/{task['id']}/claim",
        headers={"Authorization": f"Bearer {token}"},
        json={"ttl_seconds": 300},
    )
    assert claim_response.status_code == 200
    claim = claim_response.json()
    resource_fencing_tokens = {
        lease["resource"]: lease["fencing_token"] for lease in claim["resource_leases"]
    }
    opener = ClientTestOpener(client)
    ledger = CoordinationHttpDispatchLedger(
        base_url="http://127.0.0.1",
        bearer_token=token,
        opener=opener,
    )
    sends: list[StandardHttpResponse] = []

    def send_once() -> StandardHttpResponse:
        response = StandardHttpResponse(429, {"Retry-After": "30"})
        sends.append(response)
        return response

    result = dispatch_once(
        ledger=ledger,
        task_id=task["id"],
        claim_fencing_token=claim["task"]["claim_fencing_token"],
        resource_fencing_tokens=resource_fencing_tokens,
        idempotency_key="integration-call-1",
        send_once=send_once,
    )
    with pytest.raises(DispatchReservationReplay):
        dispatch_once(
            ledger=ledger,
            task_id=task["id"],
            claim_fencing_token=claim["task"]["claim_fencing_token"],
            resource_fencing_tokens=resource_fencing_tokens,
            idempotency_key="integration-call-1",
            send_once=send_once,
        )

    assert result.response is sends[0]
    assert len(sends) == 1
    task_view = client.get(f"/v1/tasks/{task['id']}", headers=admin_headers).json()
    assert task_view["dispatch_attempt_budget"]["consumed"] == 1
    assert task_view["dispatch_attempt_budget"]["provider_usage"]["status"] == "unsupported"
    receipt = opener.payloads[1]["receipt"]
    assert receipt["http_status_code"] == 429
    assert receipt["retry_after_seconds"] == 30


def test_bounded_retry_sequence_integrates_with_reference_api(client, admin_headers) -> None:
    agent_response = client.post(
        "/v1/agents",
        headers=admin_headers,
        json={"name": "dispatch-retry-integration", "owner": "tests", "role": "worker"},
    )
    assert agent_response.status_code == 201
    agent_id = agent_response.json()["id"]
    mandate_response = client.post(
        "/v1/mandates",
        headers=admin_headers,
        json={
            "agent_id": agent_id,
            "subject": f"agent:{agent_id}",
            "scopes": [{"action": "coordination.*", "resource": "task:*"}],
            "ttl_seconds": 3600,
        },
    )
    assert mandate_response.status_code == 201
    token = mandate_response.json()["token"]
    task_response = client.post(
        "/v1/tasks",
        headers=admin_headers,
        json={
            "title": "Exercise bounded dispatch retries",
            "description": "Each retry must reserve and receipt its own durable slot.",
            "acceptance_criteria": ["two reservations and two receipts"],
            "resources": ["repo:file:src/retry_integration.py"],
            "priority": 80,
            "max_dispatch_attempts": 2,
        },
    )
    assert task_response.status_code == 201
    task = task_response.json()
    claim_response = client.post(
        f"/v1/tasks/{task['id']}/claim",
        headers={"Authorization": f"Bearer {token}"},
        json={"ttl_seconds": 300},
    )
    assert claim_response.status_code == 200
    claim = claim_response.json()
    resource_fencing_tokens = {
        lease["resource"]: lease["fencing_token"] for lease in claim["resource_leases"]
    }
    opener = ClientTestOpener(client)
    ledger = CoordinationHttpDispatchLedger(
        base_url="http://127.0.0.1",
        bearer_token=token,
        opener=opener,
    )
    sends: list[tuple[str, StandardHttpResponse]] = []
    waits: list[float] = []
    responses = [
        StandardHttpResponse(
            503,
            {"Retry-After": "0"},
            {"error": {"type": "server_error"}},
        ),
        StandardHttpResponse(
            200,
            {},
            {
                "object": "response",
                "id": "resp_retry_2",
                "model": "gpt-5.6",
                "status": "completed",
                "created_at": 1_791_000_000,
                "usage": {
                    "input_tokens": 12,
                    "output_tokens": 7,
                    "total_tokens": 19,
                    "input_tokens_details": {"cached_tokens": 3},
                    "output_tokens_details": {"reasoning_tokens": 2},
                },
            },
        ),
    ]

    def send_once(provider_idempotency_key: str) -> StandardHttpResponse:
        response = responses.pop(0)
        sends.append((provider_idempotency_key, response))
        return response

    result = dispatch_with_retries(
        ledger=ledger,
        task_id=task["id"],
        claim_fencing_token=claim["task"]["claim_fencing_token"],
        resource_fencing_tokens=resource_fencing_tokens,
        idempotency_key="retry-integration-call",
        provider_idempotency_key="provider-retry-integration-key",
        send_once=send_once,
        policy=DispatchRetryPolicy(max_attempts=2, max_retry_after_seconds=1),
        wait=waits.append,
        usage_report_from_response=lambda response: parse_openai_responses_usage(
            response.json(), observed_at=datetime.fromisoformat("2026-10-13T07:00:00+00:00")
        ),
    )

    assert len(result.attempts) == 2
    assert waits == [0.0]
    assert result.response is sends[-1][1]
    assert [key for key, _ in sends] == [
        "provider-retry-integration-key",
        "provider-retry-integration-key",
    ]
    receipts = [opener.payloads[index]["receipt"] for index in (1, 3)]
    assert [receipt["http_status_code"] for receipt in receipts] == [503, 200]
    assert receipts[0]["dispatch_attempt_id"] != receipts[1]["dispatch_attempt_id"]
    assert receipts[0]["provider_usage_report"]["status"] == "missing"
    assert receipts[1]["provider_usage_report"]["status"] == "reported"
    assert receipts[1]["provider_usage_report"]["measurements"] == {
        "cached_input_tokens": 3,
        "input_tokens": 12,
        "output_tokens": 7,
        "reasoning_output_tokens": 2,
        "total_tokens": 19,
    }
    task_view = client.get(f"/v1/tasks/{task['id']}", headers=admin_headers).json()
    assert task_view["dispatch_attempt_budget"]["consumed"] == 2
    assert task_view["dispatch_attempt_budget"]["provider_usage"]["status"] == "unsupported"


def test_coordination_http_adapter_does_not_send_after_api_error_or_redirect() -> None:
    error_body_secret = "API body secret"
    opener = FakeApiOpener(
        HTTPError(
            "https://coord.example/private?token=not-logged",
            409,
            error_body_secret,
            {},
            io.BytesIO(error_body_secret.encode()),
        )
    )
    ledger = CoordinationHttpDispatchLedger(
        base_url="https://coord.example",
        bearer_token="bearer-secret",
        opener=opener,
    )

    with pytest.raises(DispatchLedgerHttpError) as failure:
        ledger.reserve_dispatch_attempt(
            task_id="task-1",
            claim_fencing_token=7,
            resource_fencing_tokens={},
            idempotency_key="call-1",
        )

    rendered = "".join(traceback.format_exception(failure.value))
    assert failure.value.status_code == 409
    assert error_body_secret not in str(failure.value)
    assert error_body_secret not in rendered
    assert "not-logged" not in rendered
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    assert len(opener.requests) == 1


def test_adapter_transport_errors_and_dispatch_callback_errors_are_sanitized() -> None:
    secret = "https://private.example/path?api_key=sentinel-secret"
    opener = FakeApiOpener(TimeoutError(secret))
    ledger = CoordinationHttpDispatchLedger(
        base_url="https://coord.example",
        bearer_token="bearer-secret",
        opener=opener,
    )
    with pytest.raises(DispatchLedgerTransportError) as transport_failure:
        ledger.reserve_dispatch_attempt(
            task_id="task-1",
            claim_fencing_token=7,
            resource_fencing_tokens={},
            idempotency_key="call-1",
        )
    rendered = "".join(traceback.format_exception(transport_failure.value))
    assert transport_failure.value.failure_type == "TimeoutError"
    assert secret not in str(transport_failure.value)
    assert secret not in rendered
    assert transport_failure.value.__cause__ is None
    assert transport_failure.value.__context__ is None

    fake_ledger = FakeLedger()
    with pytest.raises(DispatchOutcomeUnknown) as callback_failure:
        _dispatch(
            fake_ledger,
            "sanitized-callback",
            lambda: (_ for _ in ()).throw(TimeoutError(secret)),
        )
    callback_traceback = "".join(traceback.format_exception(callback_failure.value))
    assert callback_failure.value.failure_type == "TimeoutError"
    assert secret not in str(callback_failure.value)
    assert secret not in callback_traceback
    assert callback_failure.value.__cause__ is None
    assert callback_failure.value.__context__ is None


def test_http_adapter_rejects_unsafe_base_urls_and_default_refuses_redirects() -> None:
    for url in (
        "ftp://coord.example",
        "http://coord.example",
        "https://user:password@coord.example",
        "https://coord.example?token=secret",
        "https://coord.example/#fragment",
        "https://coord.example:invalid",
    ):
        with pytest.raises(ValueError):
            CoordinationHttpDispatchLedger(base_url=url, bearer_token="token")
    with pytest.raises(ValueError):
        CoordinationHttpDispatchLedger(base_url="https://coord.example", bearer_token="")
    with pytest.raises(ValueError):
        CoordinationHttpDispatchLedger(base_url="https://coord.example", bearer_token="bad token")
    with pytest.raises(ValueError):
        CoordinationHttpDispatchLedger(base_url="https://coord.example", bearer_token="non-ascii-é")

    ledger = CoordinationHttpDispatchLedger(
        base_url="https://coord.example", bearer_token="test-token"
    )
    redirect_handlers = [
        handler
        for handler in ledger._opener.handlers
        if handler.__class__.__name__ == "_NoRedirectHandler"
    ]
    assert len(redirect_handlers) == 1
    assert (
        redirect_handlers[0].redirect_request(
            Request("https://coord.example"),
            object(),
            307,
            "Temporary Redirect",
            {},
            "https://attacker.example/",
        )
        is None
    )
