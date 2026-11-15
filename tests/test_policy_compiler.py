"""Unit and parametrized compiler tests for the `.aegis` Policy-as-Code AST engine."""

from __future__ import annotations

import pytest

from aegis.policy import PolicyEngine, PolicySyntaxError, compile_policy
from aegis.types import ActionIntent, PolicyDecisionEffect, PrincipalContext


def _principal(**overrides: object) -> PrincipalContext:
    base: dict[str, object] = {
        "tenant_id": "t-1",
        "principal_id": "user-1",
        "agent_id": "agent-1",
        "roles": ("procurement_planner",),
        "max_autonomous_spend_usd": 25_000.0,
        "mfa_verified": True,
    }
    base.update(overrides)
    return PrincipalContext(**base)  # type: ignore[arg-type]


def _intent(**overrides: object) -> ActionIntent:
    base: dict[str, object] = {
        "step_name": "s1",
        "tool_name": "erp.create_purchase_order",
        "resource_type": "purchase_order",
        "operation": "create",
        "amount_usd": 5_000.0,
    }
    base.update(overrides)
    return ActionIntent(**base)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("expr", "expected_permit"),
    [
        ('principal.tenant_id == "t-1"', True),
        ('principal.tenant_id != "t-2"', True),
        ('principal.tenant_id == "t-2"', False),
        ("action.amount_usd < 10000", True),
        ("action.amount_usd <= 5000.0", True),
        ("action.amount_usd > 4999.99", True),
        ("action.amount_usd >= 5001", False),
        ('"procurement_planner" in principal.roles', True),
        ('"cfo" not in principal.roles', True),
        ('action.tool_name contains "purchase_order"', True),
        ("not (action.amount_usd > 10000)", True),
        ('principal.mfa_verified == true and action.operation in ["create", "update"]', True),
        ('principal.mfa_verified == false or action.operation == "create"', True),
        ("principal.approver_id == null", True),
        ("context.nonexistent_field == true", False),
        ("action.amount_usd > -10", True),
    ],
)
def test_policy_expression_operators(expr: str, expected_permit: bool) -> None:
    src = f"""
    # Comment header ignored by lexer
    rule "test-expr" {{
        effect: permit
        description: "Operator check"
        when: {expr}
    }}
    """
    engine = PolicyEngine.from_source(src)
    verdict = engine.evaluate(_principal(), _intent(), {"env": "prod"})
    assert verdict.permitted is expected_permit


def test_deny_overrides_conflict_resolution() -> None:
    src = """
    rule "broad-permit" {
        effect: permit
        description: "Allow all POs"
        when: action.resource_type == "purchase_order"
    }
    rule "specific-forbid" {
        effect: forbid
        description: "Block above $10k"
        when: action.amount_usd > 10000
    }
    """
    engine = PolicyEngine.from_source(src)
    ok_verdict = engine.evaluate(_principal(), _intent(amount_usd=8_000.0))
    assert ok_verdict.effect == PolicyDecisionEffect.PERMIT
    assert ok_verdict.deciding_rule_id == "broad-permit"

    deny_verdict = engine.evaluate(_principal(), _intent(amount_usd=15_000.0))
    assert deny_verdict.effect == PolicyDecisionEffect.DENY
    assert deny_verdict.deciding_rule_id == "specific-forbid"
    assert len(deny_verdict.traces) == 2


def test_implicit_default_deny_when_no_rule_matches() -> None:
    src = """
    rule "only-inventory" {
        effect: permit
        when: action.resource_type == "inventory_lot"
    }
    """
    engine = PolicyEngine.from_source(src)
    verdict = engine.evaluate(_principal(), _intent(resource_type="wire_transfer"))
    assert not verdict.permitted
    assert verdict.deciding_rule_id is None
    assert "default-deny" in verdict.reason.lower()


def test_strict_boolean_vs_integer_equality_guard() -> None:
    src = """
    rule "bool-strict" {
        effect: permit
        when: principal.mfa_verified == 1
    }
    """
    engine = PolicyEngine.from_source(src)
    verdict = engine.evaluate(_principal(mfa_verified=True), _intent())
    assert not verdict.permitted


@pytest.mark.parametrize(
    "bad_source",
    [
        'rule "dunder" { effect: permit when: principal.__class__ == "x" }',
        'rule "bad-root" { effect: permit when: system.secret == "x" }',
        'rule "bad-effect" { effect: allow when: principal.mfa_verified == true }',
        'rule "missing-when" { effect: permit description: "no condition" }',
        'rule "dup" { effect: permit when: true } rule "dup" { effect: forbid when: false }',
        'rule "unclosed-str" { effect: permit when: principal.tenant_id == "abc }',
        'rule "bad-char" { effect: permit when: principal.tenant_id == @abc }',
        'rule "unknown-field" { effect: permit priority: 1 when: true }',
    ],
)
def test_compiler_rejects_malformed_or_unsafe_policies(bad_source: str) -> None:
    with pytest.raises(PolicySyntaxError):
        compile_policy(bad_source)


def test_escaped_string_literals_in_policy() -> None:
    src = r"""
    rule "escaped" {
        effect: permit
        description: "Escaped \"quoted\" description"
        when: context.note == "line1\nline2"
    }
    """
    engine = PolicyEngine.from_source(src)
    verdict = engine.evaluate(_principal(), _intent(), {"note": "line1\nline2"})
    assert verdict.permitted
