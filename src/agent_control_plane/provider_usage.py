"""Report-only usage extraction for provider response payloads.

These observations are client-reported metadata, not authenticated provider
metering, a billing estimate, or a hard-limit enforcement signal.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

UsageReportStatus = Literal["reported", "missing", "invalid"]


@dataclass(frozen=True, slots=True)
class ClientReportedProviderUsage:
    """One provider response's client-observed usage, explicitly report-only."""

    status: UsageReportStatus
    provider: str
    adapter: str
    source: Literal["client_reported"]
    scope: Literal["single_response"]
    unit: str | None
    observed_at: str
    response_id: str | None
    model: str | None
    response_created_at: int | None
    measurements: tuple[tuple[str, int], ...]
    freshness: Literal["unknown"]
    enforcement: Literal["report_only"]
    reason: str | None

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "provider": self.provider,
            "adapter": self.adapter,
            "source": self.source,
            "scope": self.scope,
            "unit": self.unit,
            "observed_at": self.observed_at,
            "response_id": self.response_id,
            "model": self.model,
            "response_created_at": self.response_created_at,
            "measurements": dict(self.measurements),
            "freshness": self.freshness,
            "enforcement": self.enforcement,
            "reason": self.reason,
        }


def parse_openai_responses_usage(
    response: object, *, observed_at: datetime | None = None
) -> ClientReportedProviderUsage:
    """Extract token counters from a non-streaming OpenAI Responses payload.

    Missing and malformed usage are returned as bounded status records instead
    of raising after the billable provider request has already completed.
    Streaming events and in-progress responses do not prove final per-response
    usage and are reported as missing.
    """

    observed = _timestamp(observed_at)
    if not isinstance(response, Mapping) or response.get("object") != "response":
        return _report(
            status="missing",
            observed_at=observed,
            reason="provider_response_usage_object_missing",
        )

    response_id = response.get("id")
    model = response.get("model")
    response_created_at = response.get("created_at")
    if (
        not _valid_response_id(response_id)
        or not _valid_model(model)
        or (
            response_created_at is not None
            and (
                type(response_created_at) is not int or not 0 <= response_created_at <= 253402300799
            )
        )
    ):
        return _report(
            status="invalid",
            observed_at=observed,
            reason="provider_response_metadata_malformed",
        )

    if response.get("status") not in {"completed", "incomplete"}:
        return _report(
            status="missing",
            observed_at=observed,
            response_id=response_id,
            model=model,
            response_created_at=response_created_at,
            reason="provider_response_not_terminal",
        )

    usage = response.get("usage")
    if usage is None:
        return _report(
            status="missing",
            observed_at=observed,
            response_id=response_id,
            model=model,
            response_created_at=response_created_at,
            reason="provider_usage_missing",
        )
    if not isinstance(usage, Mapping):
        return _report(
            status="invalid",
            observed_at=observed,
            response_id=response_id,
            model=model,
            response_created_at=response_created_at,
            reason="provider_usage_malformed",
        )

    input_tokens = usage.get("input_tokens")
    output_tokens = usage.get("output_tokens")
    total_tokens = usage.get("total_tokens")
    if not all(_valid_count(value) for value in (input_tokens, output_tokens, total_tokens)):
        return _report(
            status="invalid",
            observed_at=observed,
            response_id=response_id,
            model=model,
            response_created_at=response_created_at,
            reason="provider_usage_malformed",
        )
    if total_tokens != input_tokens + output_tokens:
        return _report(
            status="invalid",
            observed_at=observed,
            response_id=response_id,
            model=model,
            response_created_at=response_created_at,
            reason="provider_usage_inconsistent_total",
        )

    measurements = {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
    }
    details = (
        (usage.get("input_tokens_details"), {"cached_tokens", "cache_write_tokens"}),
        (usage.get("output_tokens_details"), {"reasoning_tokens"}),
    )
    detail_names: tuple[tuple[str, str], ...] = (
        ("cached_tokens", "cached_input_tokens"),
        ("cache_write_tokens", "cache_write_input_tokens"),
        ("reasoning_tokens", "reasoning_output_tokens"),
    )
    for detail, allowed_fields in details:
        if detail is None:
            continue
        if not isinstance(detail, Mapping):
            return _report(
                status="invalid",
                observed_at=observed,
                response_id=response_id,
                model=model,
                response_created_at=response_created_at,
                reason="provider_usage_malformed",
            )
        for field in allowed_fields:
            if field in detail and not _valid_count(detail[field]):
                return _report(
                    status="invalid",
                    observed_at=observed,
                    response_id=response_id,
                    model=model,
                    response_created_at=response_created_at,
                    reason="provider_usage_malformed",
                )
        for source_name, report_name in detail_names:
            if source_name in allowed_fields and source_name in detail:
                measurements[report_name] = detail[source_name]

    return _report(
        status="reported",
        observed_at=observed,
        response_id=response_id,
        model=model,
        response_created_at=response_created_at,
        measurements=measurements,
    )


def _provider_usage_extraction_failed(
    *, observed_at: datetime | None = None
) -> ClientReportedProviderUsage:
    """Create a bounded diagnostic when a caller-supplied extractor raises."""

    return _report(
        status="invalid",
        observed_at=_timestamp(observed_at),
        provider="unknown",
        adapter="unknown",
        reason="provider_usage_extractor_failed",
    )


def _report(
    *,
    status: UsageReportStatus,
    observed_at: str,
    reason: str | None = None,
    response_id: str | None = None,
    model: str | None = None,
    response_created_at: int | None = None,
    measurements: Mapping[str, int] | None = None,
    provider: str = "openai",
    adapter: str = "responses",
) -> ClientReportedProviderUsage:
    return ClientReportedProviderUsage(
        status=status,
        provider=provider,
        adapter=adapter,
        source="client_reported",
        scope="single_response",
        unit="tokens" if status == "reported" else None,
        observed_at=observed_at,
        response_id=response_id,
        model=model,
        response_created_at=response_created_at,
        measurements=tuple(sorted((measurements or {}).items())),
        freshness="unknown",
        enforcement="report_only",
        reason=reason,
    )


def _valid_response_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("resp_")
        and 6 <= len(value) <= 256
        and value.isascii()
        and all(char.isalnum() or char in "_-" for char in value[5:])
    )


def _valid_model(value: object) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 128
        and value.isascii()
        and value[0].isalnum()
        and all(char.isalnum() or char in "._:-" for char in value)
    )


def _valid_count(value: object) -> bool:
    return type(value) is int and 0 <= value <= 2**63 - 1


def _timestamp(value: datetime | None) -> str:
    if value is None:
        value = datetime.now(UTC)
    elif value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


__all__ = [
    "ClientReportedProviderUsage",
    "parse_openai_responses_usage",
]
