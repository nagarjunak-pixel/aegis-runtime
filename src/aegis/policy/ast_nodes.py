"""Typed Abstract Syntax Tree (AST) nodes for the `.aegis` Policy-as-Code DSL."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

type LiteralScalar = str | int | float | bool | None


class RuleEffect(StrEnum):
    PERMIT = "permit"
    FORBID = "forbid"


class BinaryOperator(StrEnum):
    AND = "and"
    OR = "or"
    EQ = "=="
    NEQ = "!="
    LT = "<"
    LTE = "<="
    GT = ">"
    GTE = ">="
    IN = "in"
    NOT_IN = "not in"
    CONTAINS = "contains"


class UnaryOperator(StrEnum):
    NOT = "not"


@dataclass(frozen=True, slots=True)
class LiteralNode:
    value: LiteralScalar

    def pretty(self) -> str:
        if self.value is None:
            return "null"
        if isinstance(self.value, bool):
            return "true" if self.value else "false"
        if isinstance(self.value, str):
            return f'"{self.value}"'
        return str(self.value)


@dataclass(frozen=True, slots=True)
class ListLiteralNode:
    elements: tuple[ExprNode, ...]

    def pretty(self) -> str:
        inner = ", ".join(el.pretty() for el in self.elements)
        return f"[{inner}]"


@dataclass(frozen=True, slots=True)
class AttributePathNode:
    parts: tuple[str, ...]

    def pretty(self) -> str:
        return ".".join(self.parts)


@dataclass(frozen=True, slots=True)
class UnaryOpNode:
    op: UnaryOperator
    operand: ExprNode

    def pretty(self) -> str:
        return f"(not {self.operand.pretty()})"


@dataclass(frozen=True, slots=True)
class BinaryOpNode:
    op: BinaryOperator
    left: ExprNode
    right: ExprNode

    def pretty(self) -> str:
        return f"({self.left.pretty()} {self.op.value} {self.right.pretty()})"


type ExprNode = LiteralNode | ListLiteralNode | AttributePathNode | UnaryOpNode | BinaryOpNode


@dataclass(frozen=True, slots=True)
class PolicyRule:
    rule_id: str
    effect: RuleEffect
    description: str
    condition: ExprNode


@dataclass(frozen=True, slots=True)
class PolicySet:
    rules: tuple[PolicyRule, ...]
    source_hash: str
