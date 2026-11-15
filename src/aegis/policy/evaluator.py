"""Deterministic, side-effect-free AST evaluator implementing Deny-Overrides + Default-Deny."""

from __future__ import annotations

import time
from collections.abc import Collection, Mapping
from pathlib import Path
from typing import Any

from aegis.policy.ast_nodes import (
    AttributePathNode,
    BinaryOperator,
    BinaryOpNode,
    ExprNode,
    ListLiteralNode,
    LiteralNode,
    PolicySet,
    RuleEffect,
    UnaryOperator,
    UnaryOpNode,
)
from aegis.policy.parser import compile_policy
from aegis.policy.taint import TaintAnalyzer
from aegis.types import (
    ActionIntent,
    PolicyDecisionEffect,
    PolicyVerdict,
    PrincipalContext,
    RuleEvaluationTrace,
)


class _MissingAttr:
    """Sentinel representing an undefined attribute lookup (fail-safe non-matching)."""


_MISSING = _MissingAttr()


class PolicyEngine:
    """Formal Zero-Trust Policy Gatekeeper combining AST evaluation and taint analysis."""

    def __init__(self, policy_set: PolicySet, taint_analyzer: TaintAnalyzer | None = None) -> None:
        self._policy_set = policy_set
        self._taint_analyzer = taint_analyzer or TaintAnalyzer()

    @classmethod
    def from_source(cls, source: str) -> PolicyEngine:
        return cls(compile_policy(source))

    @classmethod
    def from_file(cls, path: str | Path) -> PolicyEngine:
        text = Path(path).read_text(encoding="utf-8")
        return cls.from_source(text)

    @property
    def policy_hash(self) -> str:
        return self._policy_set.source_hash

    @property
    def policy_set(self) -> PolicySet:
        return self._policy_set

    def evaluate(
        self,
        principal: PrincipalContext,
        action: ActionIntent,
        context: Mapping[str, Any] | None = None,
    ) -> PolicyVerdict:
        """Evaluate an ActionIntent under strict Deny-Overrides + Default-Deny semantics."""
        t0 = time.perf_counter()

        # Phase 1: Hard lattice information-flow taint check
        taint_violation_reason = self._taint_analyzer.check_action_integrity(action)
        if taint_violation_reason is not None:
            elapsed_us = (time.perf_counter() - t0) * 1_000_000.0
            return PolicyVerdict(
                effect=PolicyDecisionEffect.DENY,
                deciding_rule_id="lattice:information-flow-taint-gate",
                reason=taint_violation_reason,
                evaluation_latency_us=round(elapsed_us, 2),
                taint_violation=True,
                traces=(),
            )

        env: dict[str, Any] = {
            "principal": principal.model_dump(mode="json"),
            "action": action.model_dump(mode="json"),
            "context": dict(context or {}),
        }

        traces: list[RuleEvaluationTrace] = []
        matching_forbid_id: str | None = None
        matching_forbid_desc: str | None = None
        matching_permit_id: str | None = None
        matching_permit_desc: str | None = None

        for rule in self._policy_set.rules:
            raw_val = self._eval_expr(rule.condition, env)
            matched = bool(raw_val is True)
            traces.append(
                RuleEvaluationTrace(
                    rule_id=rule.rule_id,
                    effect=rule.effect.value,
                    matched=matched,
                    description=rule.description,
                    expression_repr=rule.condition.pretty(),
                )
            )
            if matched:
                if rule.effect == RuleEffect.FORBID and matching_forbid_id is None:
                    matching_forbid_id = rule.rule_id
                    matching_forbid_desc = rule.description
                elif rule.effect == RuleEffect.PERMIT and matching_permit_id is None:
                    matching_permit_id = rule.rule_id
                    matching_permit_desc = rule.description

        elapsed_us = (time.perf_counter() - t0) * 1_000_000.0

        if matching_forbid_id is not None:
            return PolicyVerdict(
                effect=PolicyDecisionEffect.DENY,
                deciding_rule_id=matching_forbid_id,
                reason=f"Explicitly forbidden by rule '{matching_forbid_id}': {matching_forbid_desc}",
                evaluation_latency_us=round(elapsed_us, 2),
                taint_violation=False,
                traces=tuple(traces),
            )

        if matching_permit_id is not None:
            return PolicyVerdict(
                effect=PolicyDecisionEffect.PERMIT,
                deciding_rule_id=matching_permit_id,
                reason=f"Permitted by rule '{matching_permit_id}': {matching_permit_desc}",
                evaluation_latency_us=round(elapsed_us, 2),
                taint_violation=False,
                traces=tuple(traces),
            )

        return PolicyVerdict(
            effect=PolicyDecisionEffect.DENY,
            deciding_rule_id=None,
            reason="Implicit default-deny: no matching permit rule satisfied",
            evaluation_latency_us=round(elapsed_us, 2),
            taint_violation=False,
            traces=tuple(traces),
        )

    def _eval_expr(self, node: ExprNode, env: Mapping[str, Any]) -> Any:
        if isinstance(node, LiteralNode):
            return node.value

        if isinstance(node, ListLiteralNode):
            return [self._eval_expr(el, env) for el in node.elements]

        if isinstance(node, AttributePathNode):
            curr: Any = env
            for part in node.parts:
                if part.startswith("__"):
                    return _MISSING
                if isinstance(curr, Mapping) and part in curr:
                    curr = curr[part]
                else:
                    return _MISSING
            return curr

        if isinstance(node, UnaryOpNode):
            val = self._eval_expr(node.operand, env)
            if isinstance(val, _MissingAttr):
                return False
            if node.op == UnaryOperator.NOT:
                return not bool(val)

        if isinstance(node, BinaryOpNode):
            if node.op == BinaryOperator.AND:
                lhs = self._eval_expr(node.left, env)
                if lhs is not True:
                    return False
                rhs = self._eval_expr(node.right, env)
                return bool(rhs is True)

            if node.op == BinaryOperator.OR:
                lhs = self._eval_expr(node.left, env)
                if lhs is True:
                    return True
                rhs = self._eval_expr(node.right, env)
                return bool(rhs is True)

            lhs = self._eval_expr(node.left, env)
            rhs = self._eval_expr(node.right, env)
            if isinstance(lhs, _MissingAttr) or isinstance(rhs, _MissingAttr):
                return False

            if node.op == BinaryOperator.EQ:
                if type(lhs) is bool or type(rhs) is bool:
                    return type(lhs) is type(rhs) and lhs == rhs
                return bool(lhs == rhs)

            if node.op == BinaryOperator.NEQ:
                if type(lhs) is bool or type(rhs) is bool:
                    return not (type(lhs) is type(rhs) and lhs == rhs)
                return bool(lhs != rhs)

            if node.op in (
                BinaryOperator.LT,
                BinaryOperator.LTE,
                BinaryOperator.GT,
                BinaryOperator.GTE,
            ):
                if (
                    not isinstance(lhs, (int, float))
                    or not isinstance(rhs, (int, float))
                    or isinstance(lhs, bool)
                    or isinstance(rhs, bool)
                ):
                    return False
                if node.op == BinaryOperator.LT:
                    return lhs < rhs
                if node.op == BinaryOperator.LTE:
                    return lhs <= rhs
                if node.op == BinaryOperator.GT:
                    return lhs > rhs
                return lhs >= rhs

            if node.op == BinaryOperator.IN:
                if isinstance(rhs, Collection) and not isinstance(rhs, (str, bytes)):
                    return lhs in rhs
                return False

            if node.op == BinaryOperator.NOT_IN:
                if isinstance(rhs, Collection) and not isinstance(rhs, (str, bytes)):
                    return lhs not in rhs
                return False

            if node.op == BinaryOperator.CONTAINS:
                if isinstance(lhs, str) and isinstance(rhs, str):
                    return rhs in lhs
                if isinstance(lhs, Collection) and not isinstance(lhs, (str, bytes)):
                    return rhs in lhs
                return False

        return False
