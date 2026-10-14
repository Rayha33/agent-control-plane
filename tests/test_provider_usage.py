from __future__ import annotations

from datetime import datetime

import pytest

from agent_control_plane.coordination_schemas import (
    ProviderUsageReport,
    ProviderUsageSummaryGroup,
)
from agent_control_plane.provider_usage import (
    parse_anthropic_messages_usage,
    parse_gemini_generate_content_usage,
    parse_openai_responses_usage,
)

OBSERVED_AT = datetime.fromisoformat("2026-10-13T07:00:00+00:00")


def _response(**overrides):
    response = {
        "object": "response",
        "id": "resp_usage_1",
        "model": "gpt-5.6",
        "status": "completed",
        "created_at": 1_791_000_000,
        "usage": {
            "input_tokens": 21,
            "output_tokens": 9,
            "total_tokens": 30,
            "input_tokens_details": {
                "cached_tokens": 4,
                "cache_write_tokens": 2,
            },
            "output_tokens_details": {"reasoning_tokens": 3},
        },
    }
    response.update(overrides)
    return response


def test_openai_responses_usage_is_a_report_only_per_response_observation() -> None:
    report = parse_openai_responses_usage(_response(), observed_at=OBSERVED_AT).as_dict()

    assert report == {
        "status": "reported",
        "provider": "openai",
        "adapter": "responses",
        "source": "client_reported",
        "scope": "single_response",
        "unit": "tokens",
        "observed_at": "2026-10-13T07:00:00Z",
        "response_id": "resp_usage_1",
        "model": "gpt-5.6",
        "response_created_at": 1_791_000_000,
        "measurements": {
            "cached_input_tokens": 4,
            "cache_write_input_tokens": 2,
            "input_tokens": 21,
            "output_tokens": 9,
            "reasoning_output_tokens": 3,
            "total_tokens": 30,
        },
        "freshness": "unknown",
        "enforcement": "report_only",
        "reason": None,
    }


def test_anthropic_messages_usage_normalizes_cached_input_and_validates_contract() -> None:
    response = {
        "type": "message",
        "id": "msg_01Abcdef",
        "model": "claude-sonnet-4-6",
        "stop_reason": "end_turn",
        "usage": {
            "input_tokens": 10,
            "cache_creation_input_tokens": 5,
            "cache_read_input_tokens": 100,
            "output_tokens": 7,
            "output_tokens_details": {"thinking_tokens": 2},
        },
    }

    report = parse_anthropic_messages_usage(response, observed_at=OBSERVED_AT).as_dict()

    assert report == {
        "status": "reported",
        "provider": "anthropic",
        "adapter": "messages",
        "source": "client_reported",
        "scope": "single_response",
        "unit": "tokens",
        "observed_at": "2026-10-13T07:00:00Z",
        "response_id": "msg_01Abcdef",
        "model": "claude-sonnet-4-6",
        "response_created_at": None,
        "measurements": {
            "cached_input_tokens": 100,
            "cache_write_input_tokens": 5,
            "input_tokens": 115,
            "output_tokens": 7,
            "reasoning_output_tokens": 2,
            "total_tokens": 122,
        },
        "freshness": "unknown",
        "enforcement": "report_only",
        "reason": None,
    }
    ProviderUsageReport.model_validate(report)
    ProviderUsageSummaryGroup.model_validate(
        {
            "provider": report["provider"],
            "adapter": report["adapter"],
            "model": report["model"],
            "response_count": 1,
            "latest_client_observed_at": report["observed_at"],
            "measurements": report["measurements"],
            "measurement_response_counts": {name: 1 for name in report["measurements"]},
        }
    )


@pytest.mark.parametrize(
    "usage",
    [
        {"input_tokens": True, "output_tokens": 1},
        {"input_tokens": 1, "output_tokens": -1},
        {"input_tokens": 2**63 - 1, "output_tokens": 1},
        {"input_tokens": 1, "output_tokens": 1, "cache_read_input_tokens": True},
        {"input_tokens": 1, "output_tokens": 1, "output_tokens_details": []},
        {
            "input_tokens": 1,
            "output_tokens": 1,
            "output_tokens_details": {"thinking_tokens": 2},
        },
    ],
)
def test_anthropic_malformed_usage_never_becomes_a_token_report(usage) -> None:
    response = {
        "type": "message",
        "id": "msg_01Abcdef",
        "model": "claude-sonnet-4-6",
        "stop_reason": "end_turn",
        "usage": usage,
    }

    report = parse_anthropic_messages_usage(response, observed_at=OBSERVED_AT).as_dict()

    assert report["status"] == "invalid"
    assert report["measurements"] == {}
    assert report["reason"] == "provider_usage_malformed"


def test_anthropic_streaming_message_start_usage_is_not_terminal() -> None:
    response = {
        "type": "message",
        "id": "msg_01Abcdef",
        "model": "claude-sonnet-4-6",
        "content": [],
        "stop_reason": None,
        "stop_sequence": None,
        "usage": {
            "input_tokens": 10,
            "cache_creation_input_tokens": 0,
            "cache_read_input_tokens": 0,
            "output_tokens": 1,
        },
    }

    report = parse_anthropic_messages_usage(response, observed_at=OBSERVED_AT).as_dict()

    assert report["status"] == "missing"
    assert report["measurements"] == {}
    assert report["reason"] == "provider_response_not_terminal"


def test_gemini_usage_includes_thinking_tokens_in_normalized_output() -> None:
    response = {
        "responseId": "geminiResponse_123",
        "modelVersion": "gemini-2.5-pro",
        "usageMetadata": {
            "promptTokenCount": 10,
            "cachedContentTokenCount": 4,
            "candidatesTokenCount": 6,
            "thoughtsTokenCount": 3,
            "toolUsePromptTokenCount": 2,
            "totalTokenCount": 19,
        },
    }

    report = parse_gemini_generate_content_usage(response, observed_at=OBSERVED_AT).as_dict()

    assert report == {
        "status": "reported",
        "provider": "gemini",
        "adapter": "generate_content",
        "source": "client_reported",
        "scope": "single_response",
        "unit": "tokens",
        "observed_at": "2026-10-13T07:00:00Z",
        "response_id": "geminiResponse_123",
        "model": "gemini-2.5-pro",
        "response_created_at": None,
        "measurements": {
            "cached_input_tokens": 4,
            "input_tokens": 10,
            "output_tokens": 9,
            "reasoning_output_tokens": 3,
            "tool_use_prompt_tokens": 2,
            "total_tokens": 19,
        },
        "freshness": "unknown",
        "enforcement": "report_only",
        "reason": None,
    }
    ProviderUsageReport.model_validate(report)
    ProviderUsageSummaryGroup.model_validate(
        {
            "provider": report["provider"],
            "adapter": report["adapter"],
            "model": report["model"],
            "response_count": 1,
            "latest_client_observed_at": report["observed_at"],
            "measurements": report["measurements"],
            "measurement_response_counts": {name: 1 for name in report["measurements"]},
        }
    )


@pytest.mark.parametrize(
    ("usage", "reason"),
    [
        (
            {"promptTokenCount": True, "candidatesTokenCount": 1, "totalTokenCount": 2},
            "provider_usage_malformed",
        ),
        (
            {"promptTokenCount": 1, "candidatesTokenCount": 1, "totalTokenCount": 3},
            "provider_usage_inconsistent_total",
        ),
        (
            {
                "promptTokenCount": 1,
                "candidatesTokenCount": 1,
                "thoughtsTokenCount": -1,
                "totalTokenCount": 2,
            },
            "provider_usage_malformed",
        ),
        (
            {
                "promptTokenCount": 1,
                "cachedContentTokenCount": 2,
                "candidatesTokenCount": 1,
                "totalTokenCount": 2,
            },
            "provider_usage_malformed",
        ),
    ],
)
def test_gemini_malformed_or_inconsistent_usage_is_not_reported(usage, reason) -> None:
    response = {
        "responseId": "geminiResponse_123",
        "modelVersion": "gemini-2.5-pro",
        "usageMetadata": usage,
    }

    report = parse_gemini_generate_content_usage(response, observed_at=OBSERVED_AT).as_dict()

    assert report["status"] == "invalid"
    assert report["measurements"] == {}
    assert report["reason"] == reason


def test_unknown_provider_response_shapes_remain_bounded_missing_reports() -> None:
    anthropic = parse_anthropic_messages_usage(
        {"error": {"message": "private"}}, observed_at=OBSERVED_AT
    )
    gemini = parse_gemini_generate_content_usage(
        {"error": {"message": "private"}}, observed_at=OBSERVED_AT
    )

    assert anthropic.status == gemini.status == "missing"
    assert anthropic.measurements == gemini.measurements == ()
    assert "private" not in repr(anthropic)
    assert "private" not in repr(gemini)


@pytest.mark.parametrize(
    ("response", "reason"),
    [
        ({"error": {"type": "rate_limit_error"}}, "provider_response_usage_object_missing"),
        (
            _response(status="in_progress"),
            "provider_response_not_terminal",
        ),
        (_response(usage=None), "provider_usage_missing"),
    ],
)
def test_missing_usage_is_reported_without_inventing_counts(response, reason) -> None:
    report = parse_openai_responses_usage(response, observed_at=OBSERVED_AT).as_dict()

    assert report["status"] == "missing"
    assert report["unit"] is None
    assert report["measurements"] == {}
    assert report["freshness"] == "unknown"
    assert report["enforcement"] == "report_only"
    assert report["reason"] == reason


@pytest.mark.parametrize("created_at", [-1, 253_402_300_800, True])
def test_invalid_provider_response_timestamp_is_not_persisted(created_at) -> None:
    report = parse_openai_responses_usage(
        _response(created_at=created_at), observed_at=OBSERVED_AT
    ).as_dict()

    assert report["status"] == "invalid"
    assert report["response_created_at"] is None
    assert report["measurements"] == {}
    assert report["reason"] == "provider_response_metadata_malformed"


@pytest.mark.parametrize(
    "usage",
    [
        {"input_tokens": True, "output_tokens": 1, "total_tokens": 2},
        {"input_tokens": -1, "output_tokens": 1, "total_tokens": 0},
        {"input_tokens": 1, "output_tokens": 1, "total_tokens": 3},
        {"input_tokens": 1, "output_tokens": 1},
        {
            "input_tokens": 1,
            "output_tokens": 1,
            "total_tokens": 2,
            "output_tokens_details": {"reasoning_tokens": True},
        },
    ],
)
def test_malformed_usage_is_reported_as_invalid_without_raw_payload(usage) -> None:
    report = parse_openai_responses_usage(_response(usage=usage), observed_at=OBSERVED_AT).as_dict()

    assert report["status"] == "invalid"
    assert report["unit"] is None
    assert report["measurements"] == {}
    assert report["reason"] in {
        "provider_usage_malformed",
        "provider_usage_inconsistent_total",
    }
    assert "True" not in str(report)
