from __future__ import annotations

from fnmatch import fnmatchcase
from typing import Any


def matches(pattern: str, value: str) -> bool:
    return fnmatchcase(value, pattern)


def scope_allows(scopes: list[dict[str, str]], action: str, resource: str) -> bool:
    return any(
        matches(scope["action"], action) and matches(scope["resource"], resource)
        for scope in scopes
    )


def pattern_is_delegable(child_pattern: str, parent_pattern: str) -> bool:
    if child_pattern == parent_pattern or parent_pattern == "*":
        return True
    if any(character in child_pattern for character in "*?["):
        return False
    return matches(parent_pattern, child_pattern)


def scope_is_delegable(child_scope: dict[str, str], parent_scopes: list[dict[str, str]]) -> bool:
    return any(
        pattern_is_delegable(child_scope["action"], parent["action"])
        and pattern_is_delegable(child_scope["resource"], parent["resource"])
        for parent in parent_scopes
    )


def policy_matches(policy: Any, action: str, resource: str) -> bool:
    return matches(policy["action_pattern"], action) and matches(
        policy["resource_pattern"], resource
    )


def amount_from_context(context: dict[str, Any]) -> int | None:
    amount = context.get("amount_cents")
    if amount is None:
        return None
    if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0:
        raise ValueError("context.amount_cents must be a non-negative integer")
    return amount
