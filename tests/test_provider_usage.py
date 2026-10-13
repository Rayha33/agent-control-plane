from __future__ import annotations

from datetime import datetime

import pytest

from agent_control_plane.provider_usage import parse_openai_responses_usage

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
