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


def parse_anthropic_messages_usage(
    response: object, *, observed_at: datetime | None = None
) -> ClientReportedProviderUsage:
    """Extract token counters from a non-streaming Anthropic Messages payload.

    Anthropic reports cache-read and cache-creation input separately. The
    normalized input count includes all three provider fields; cache counts are
    retained as detail fields. These are still client-reported observations.
    """

    observed = _timestamp(observed_at)
    if not isinstance(response, Mapping) or response.get("type") != "message":
        return _report(
            status="missing",
            observed_at=observed,
            provider="anthropic",
            adapter="messages",
            reason="provider_response_usage_object_missing",
        )

    response_id = response.get("id")
    model = response.get("model")
    stop_reason = response.get("stop_reason")
    if not _valid_prefixed_response_id(response_id, "msg_") or not _valid_model(model):
        return _report(
            status="invalid",
            observed_at=observed,
            provider="anthropic",
            adapter="messages",
            reason="provider_response_metadata_malformed",
        )
    if stop_reason is None:
        return _report(
            status="missing",
            observed_at=observed,
            provider="anthropic",
            adapter="messages",
            response_id=response_id,
            model=model,
            reason="provider_response_not_terminal",
        )
    if not isinstance(stop_reason, str) or not stop_reason:
        return _report(
            status="invalid",
            observed_at=observed,
            provider="anthropic",
            adapter="messages",
            reason="provider_response_metadata_malformed",
        )

    usage = response.get("usage")
    if usage is None:
        return _report(
            status="missing",
            observed_at=observed,
            provider="anthropic",
            adapter="messages",
            response_id=response_id,
            model=model,
            reason="provider_usage_missing",
        )
    if not isinstance(usage, Mapping):
        return _report(
            status="invalid",
            observed_at=observed,
            provider="anthropic",
            adapter="messages",
            response_id=response_id,
            model=model,
            reason="provider_usage_malformed",
        )

    input_tokens = usage.get("input_tokens")
    output_tokens = usage.get("output_tokens")
    cache_write_tokens = usage.get("cache_creation_input_tokens", 0)
    cached_tokens = usage.get("cache_read_input_tokens", 0)
    output_details = usage.get("output_tokens_details")
    reasoning_tokens = 0
    if output_details is not None:
        if not isinstance(output_details, Mapping):
            return _anthropic_invalid_usage(observed, response_id, model)
        reasoning_tokens = output_details.get("thinking_tokens", 0)
    if not all(
        _valid_count(value)
        for value in (
            input_tokens,
            output_tokens,
            cache_write_tokens,
            cached_tokens,
            reasoning_tokens,
        )
    ):
        return _anthropic_invalid_usage(observed, response_id, model)

    normalized_input = input_tokens + cache_write_tokens + cached_tokens
    total_tokens = normalized_input + output_tokens
    if reasoning_tokens > output_tokens or normalized_input > 2**63 - 1 or total_tokens > 2**63 - 1:
        return _anthropic_invalid_usage(observed, response_id, model)

    measurements = {
        "input_tokens": normalized_input,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
    }
    if "cache_creation_input_tokens" in usage:
        measurements["cache_write_input_tokens"] = cache_write_tokens
    if "cache_read_input_tokens" in usage:
        measurements["cached_input_tokens"] = cached_tokens
    if output_details is not None and "thinking_tokens" in output_details:
        measurements["reasoning_output_tokens"] = reasoning_tokens

    return _report(
        status="reported",
        observed_at=observed,
        provider="anthropic",
        adapter="messages",
        response_id=response_id,
        model=model,
        measurements=measurements,
    )


def parse_gemini_generate_content_usage(
    response: object, *, observed_at: datetime | None = None
) -> ClientReportedProviderUsage:
    """Extract Google AI Gemini Developer API GenerateContent usage.

    This parser is not for Vertex AI: Vertex has distinct total-token accounting
    and requires its own provider adapter.
    """

    observed = _timestamp(observed_at)
    if not isinstance(response, Mapping):
        return _report(
            status="missing",
            observed_at=observed,
            provider="gemini",
            adapter="generate_content",
            reason="provider_response_usage_object_missing",
        )

    response_id = response.get("responseId")
    model = response.get("modelVersion")
    if response_id is None or model is None:
        return _report(
            status="missing",
            observed_at=observed,
            provider="gemini",
            adapter="generate_content",
            reason="provider_response_usage_object_missing",
        )
    if not _valid_provider_response_id(response_id) or not _valid_model(model):
        return _report(
            status="invalid",
            observed_at=observed,
            provider="gemini",
            adapter="generate_content",
            reason="provider_response_metadata_malformed",
        )

    usage = response.get("usageMetadata")
    if usage is None:
        return _report(
            status="missing",
            observed_at=observed,
            provider="gemini",
            adapter="generate_content",
            response_id=response_id,
            model=model,
            reason="provider_usage_missing",
        )
    if not isinstance(usage, Mapping):
        return _gemini_invalid_usage(observed, response_id, model)

    prompt_tokens = usage.get("promptTokenCount")
    candidates_tokens = usage.get("candidatesTokenCount")
    total_tokens = usage.get("totalTokenCount")
    optional_fields = {
        "cachedContentTokenCount": "cached_input_tokens",
        "thoughtsTokenCount": "reasoning_output_tokens",
        "toolUsePromptTokenCount": "tool_use_prompt_tokens",
    }
    details: dict[str, int] = {}
    for field_name, report_name in optional_fields.items():
        value = usage.get(field_name)
        if value is not None:
            if not _valid_count(value):
                return _gemini_invalid_usage(observed, response_id, model)
            details[report_name] = value

    if not all(_valid_count(value) for value in (prompt_tokens, candidates_tokens, total_tokens)):
        return _gemini_invalid_usage(observed, response_id, model)
    if details.get("cached_input_tokens", 0) > prompt_tokens:
        return _gemini_invalid_usage(observed, response_id, model)
    reasoning_tokens = details.get("reasoning_output_tokens", 0)
    normalized_output = candidates_tokens + reasoning_tokens
    if (
        normalized_output > 2**63 - 1
        or prompt_tokens + normalized_output > 2**63 - 1
        or total_tokens != prompt_tokens + normalized_output
    ):
        return _report(
            status="invalid",
            observed_at=observed,
            provider="gemini",
            adapter="generate_content",
            response_id=response_id,
            model=model,
            reason="provider_usage_inconsistent_total",
        )

    measurements = {
        "input_tokens": prompt_tokens,
        "output_tokens": normalized_output,
        "total_tokens": total_tokens,
        **details,
    }
    return _report(
        status="reported",
        observed_at=observed,
        provider="gemini",
        adapter="generate_content",
        response_id=response_id,
        model=model,
        measurements=measurements,
    )


def _anthropic_invalid_usage(
    observed_at: str, response_id: str, model: str
) -> ClientReportedProviderUsage:
    return _report(
        status="invalid",
        observed_at=observed_at,
        provider="anthropic",
        adapter="messages",
        response_id=response_id,
        model=model,
        reason="provider_usage_malformed",
    )


def _gemini_invalid_usage(
    observed_at: str, response_id: str, model: str
) -> ClientReportedProviderUsage:
    return _report(
        status="invalid",
        observed_at=observed_at,
        provider="gemini",
        adapter="generate_content",
        response_id=response_id,
        model=model,
        reason="provider_usage_malformed",
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


def _valid_prefixed_response_id(value: object, prefix: str) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(prefix)
        and 6 <= len(value) <= 256
        and value.isascii()
        and all(char.isalnum() or char in "_-" for char in value[len(prefix) :])
    )


def _valid_provider_response_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and 6 <= len(value) <= 256
        and value.isascii()
        and value[0].isalnum()
        and all(char.isalnum() or char in "_.:-" for char in value)
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
    "parse_anthropic_messages_usage",
    "parse_gemini_generate_content_usage",
    "parse_openai_responses_usage",
]
